#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Item 9 failure matrix: crash/interruption + resume per phase (autocommit,
journal retirement, coordinator, fanout), permission errors, storage
exhaustion (injected ENOSPC and real RLIMIT_FSIZE/EFBIG), and concurrent
writers/readers/contexts. Private /tmp scratch only."""
import json,os,pathlib,resource,signal,subprocess,tempfile,threading,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1]
SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def q(s):return "'"+str(s).replace("'","''")+"'"
SCHEMA="TABLE (r DIRECTORY RECORD (title TEXT, age INT64 [0-1])) LINKS INTERNAL"
class Base(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-fm-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name)
  self.addCleanup(lambda:subprocess.run(['chmod','-R','u+rwx',str(self.base)]))
  self.env={k:v for k,v in os.environ.items() if k not in('SQL_CONTEXT','DATABASE_DIR','SQL_TEST_CRASH','SQL_TEST_FAIL')};self.env['DATABASE_DIR']=str(self.base)
  self.t=self.base/'t';self.t.mkdir();self.sql('create',SCHEMA);self.sql('insert',"RECORD a (title,age) VALUES ('old',1)")
 def sql(self,verb,text='',status=0,cwd=None,env=None,ctx=None,pre=None):
  e=dict(self.env)
  if env:e.update(env)
  if ctx:e['SQL_CONTEXT']=ctx
  p=subprocess.run([str(SQL),verb,text],cwd=cwd or self.t,env=e,capture_output=True,timeout=60,preexec_fn=pre)
  if status is not None:self.assertEqual(p.returncode,status,(verb,text,p.returncode,p.stdout,p.stderr))
  return p
 def row(self,cwd=None):return json.loads(self.sql('select',"title, age WHERE record='a'",cwd=cwd).stdout)
 def journals(self,root=None):return sorted(n for n in os.listdir(root or self.t) if n.startswith(('.sql-txn.','.sql-clean.','.sql-coord.')))
 def owner(self):
  p=subprocess.Popen(['sleep','300']);self.addCleanup(p.kill);return p.pid
 def ctx(self):return self.sql('context',f'CREATE ON {q(self.base)} OWNER {self.owner()}').stdout.decode().strip()
class AutocommitCrash(Base):
 POINTS=[('command-accepted',94,'old'),('command-executing',95,'old'),('after-decision',86,'new'),('journal-after-retire',91,'new'),
         ('journal-during-gc',92,'new'),('journal-after-proof-remove',93,'new'),('command-before-ack',99,'new')]
 def autoctx(self):
  hits=[p for p in self.base.rglob(str(os.getpid())) if p.parent.name=='.context'];self.assertEqual(len(hits),1,hits);return hits[0]
 def test_every_phase_is_atomic_and_recoverable(self):
  # The autocommit context belongs to this (live) test process; a crashed
  # command is retained until its owner RESUMEs it (or RECOVER applies it).
  for point,code,expect in self.POINTS:
   with self.subTest(point=point):
    self.sql('update',"SET title='old', age=1 ALL RECORDS")
    self.sql('update',"SET title='new', age=2 ALL RECORDS",env={'SQL_TEST_CRASH':point},status=code)
    p=self.sql('select','title, age',status=None);self.assertIn(p.returncode,(0,6),p.stderr)
    if p.returncode==0:self.assertEqual(json.loads(p.stdout),[[expect,1 if expect=='old' else 2]])
    self.sql('context','RESUME '+q(self.autoctx()));self.sql('recover','TABLE . ALL APPLY')
    self.assertEqual(self.row(),[[expect,1 if expect=='old' else 2]]);self.assertEqual(self.journals(),[])
    self.sql('update',"SET age=3 ALL RECORDS");self.assertEqual(self.row()[0][1],3)
 def test_recover_report_only_changes_nothing(self):
  self.sql('update',"SET title='new' ALL RECORDS",env={'SQL_TEST_CRASH':'after-decision'},status=86);self.sql('context','RESUME '+q(self.autoctx()))
  j=self.journals();self.sql('recover','TABLE . ALL REPORT ONLY');self.assertEqual(self.journals(),j)
 def test_insert_and_delete_crash_after_decision(self):
  self.sql('insert',"RECORD b (title) VALUES ('b')",env={'SQL_TEST_CRASH':'after-decision'},status=86);self.sql('context','RESUME '+q(self.autoctx()));self.sql('recover','TABLE . ALL APPLY')
  self.assertTrue((self.t/'b'/'title').exists())
  self.sql('delete',"WHERE record='b'",env={'SQL_TEST_CRASH':'after-decision'},status=86);self.sql('context','RESUME '+q(self.autoctx()));self.sql('recover','TABLE . ALL APPLY');self.assertFalse((self.t/'b').exists())
 def test_ddl_crash_after_decision(self):
  self.sql('alter',"TABLE ADD FIELD note TEXT [0-1]",env={'SQL_TEST_CRASH':'after-decision'},status=86);self.sql('context','RESUME '+q(self.autoctx()));self.sql('recover','TABLE . ALL APPLY')
  self.assertIn('note',self.sql('describe','TABLE AS DDL').stdout.decode())
class CoordinatorCrash(Base):
 def setUp(self):
  super().setUp();self.o=self.base/'o';self.o.mkdir();self.sql('create',SCHEMA,cwd=self.o);self.sql('insert',"RECORD a (title,age) VALUES ('old',1)",cwd=self.o)
 def test_after_done_and_participant_prepare_failure(self):
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.sql('update',"SET title='x' ALL RECORDS",ctx=c);self.sql('update',f"{q(self.o)} SET title='x' ALL RECORDS",ctx=c)
  self.sql('commit','',ctx=c,env={'SQL_TEST_FAIL':'coordinator-participant-prepare'},status=3)
  self.assertEqual(self.row()[0][0],'old');self.assertEqual(self.row(self.o)[0][0],'old')
  self.sql('commit','',ctx=c,env={'SQL_TEST_CRASH':'coordinator-after-done'},status=90)
  self.sql('recover',f'DATABASE {q(self.base)} ALL APPLY')
  self.assertEqual(self.row()[0][0],'x');self.assertEqual(self.row(self.o)[0][0],'x')
  self.assertEqual(self.journals(),[]);self.assertEqual(self.journals(self.o),[])
 def test_resume_commit_after_decision_crash_is_idempotent(self):
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.sql('update',"SET title='y' ALL RECORDS",ctx=c);self.sql('update',f"{q(self.o)} SET title='y' ALL RECORDS",ctx=c)
  self.sql('commit','',ctx=c,env={'SQL_TEST_CRASH':'coordinator-after-first-apply'},status=89)
  self.sql('commit','',ctx=c);self.sql('commit','',ctx=c,status=None)
  self.assertEqual(self.row()[0][0],'y');self.assertEqual(self.row(self.o)[0][0],'y')
class Permissions(Base):
 def chmod(self,path,mode):
  old=path.stat().st_mode&0o777;path.chmod(mode);self.addCleanup(path.chmod,old)
 def test_readonly_table_root_refused_before_journal(self):
  self.chmod(self.t,0o500);p=self.sql('update',"SET title='no' ALL RECORDS",status=3);self.assertIn(b'Permission denied',p.stderr)
  self.assertEqual(self.row(),[['old',1]]);self.assertEqual(self.journals(),[])
 def test_readonly_record_dir_refused_before_decision(self):
  self.chmod(self.t/'a',0o500);p=self.sql('update',"SET title='no' ALL RECORDS",status=3);self.assertIn(b'nothing committed',p.stderr)
  self.assertEqual(self.row(),[['old',1]]);self.assertEqual(self.journals(),[]);(self.t/'a').chmod(0o700);self.sql('update',"SET title='yes' ALL RECORDS")
 def test_readonly_events_dir_refused_before_decision(self):
  self.chmod(self.t/'.sql'/'events',0o500);self.sql('update',"SET title='no' ALL RECORDS",status=3);self.assertEqual(self.row(),[['old',1]]);self.assertEqual(self.journals(),[])
 def test_unreadable_member_is_io_error_not_null(self):
  self.chmod(self.t/'a'/'title',0o000);p=self.sql('select','title',status=3);self.assertEqual(p.stdout,b'')
  self.sql('update',"SET age=5 ALL RECORDS",status=3)
 def test_new_group_under_readonly_parent(self):
  self.sql('create',"TABLE (g DIRECTORY (r DIRECTORY RECORD (title TEXT)))",cwd=self.base/'t2' if (self.base/'t2').mkdir() is None else None)
  t2=self.base/'t2';self.chmod(t2,0o500);self.sql('insert',"RECORD 'g1/r1' (title) VALUES ('x')",cwd=t2,status=3);t2.chmod(0o700);self.assertFalse((t2/'g1').exists())
class Storage(Base):
 def test_injected_payload_enospc(self):
  p=self.sql('update',"SET title='full' ALL RECORDS",env={'SQL_TEST_FAIL':'payload-enospc'},status=3);self.assertIn(b'No space left on device',p.stderr)
  self.assertEqual(self.row(),[['old',1]]);self.assertEqual(self.journals(),[])
 def test_injected_manifest_enospc_all_verbs(self):
  for verb,text in [('insert',"RECORD z (title) VALUES ('z')"),('update',"SET title='z' ALL RECORDS"),('delete','ALL RECORDS'),('alter','TABLE ADD FIELD n TEXT [0-1]')]:
   with self.subTest(verb=verb):
    p=self.sql(verb,text,env={'SQL_TEST_FAIL':'manifest-enospc'},status=3);self.assertIn(b'No space left on device',p.stderr);self.assertEqual(self.journals(),[])
  self.assertEqual(self.row(),[['old',1]]);self.assertFalse((self.t/'z').exists())
 def test_real_file_size_limit_streamed_input(self):
  big=self.base/'big.txt'
  with big.open('wb') as f:
   for _ in range(80):f.write(b'x'*(1<<20))
  def limit():
   signal.signal(signal.SIGXFSZ,signal.SIG_IGN);resource.setrlimit(resource.RLIMIT_FSIZE,(8<<20,8<<20))
  p=self.sql('update',f"SET title=FILE({q(big)}) ALL RECORDS",pre=limit,status=3);self.assertIn(b'File too large',p.stderr)
  self.assertEqual(self.row(),[['old',1]]);self.assertEqual(self.journals(),[]);self.sql('update',"SET title='fine' ALL RECORDS")
class Concurrency(Base):
 def test_parallel_inserts_all_commit(self):
  ps=[subprocess.Popen([str(SQL),'insert',f"RECORD p{i} (title,age) VALUES ('t',{i})"],cwd=self.t,env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for i in range(16)]
  self.assertEqual([p.wait(60) for p in ps],[0]*16);self.assertEqual(len(json.loads(self.sql('select','record').stdout)),17);self.assertEqual(self.journals(),[])
 def test_parallel_updates_serialize_whole_statements(self):
  ps=[subprocess.Popen([str(SQL),'update',f"SET title='v{i}', age={i} ALL RECORDS"],cwd=self.t,env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for i in range(16)]
  self.assertEqual([p.wait(60) for p in ps],[0]*16);t,a=self.row()[0];self.assertEqual(t,f'v{a}')
 def test_readers_never_see_torn_statements(self):
  stop=threading.Event();bad=[]
  def reader():
   while not stop.is_set():
    p=subprocess.run([str(SQL),'select',"title, age WHERE record='a'"],cwd=self.t,env=self.env,capture_output=True,timeout=30)
    if p.returncode==0:
     t,a=json.loads(p.stdout)[0]
     if t!=('old' if a==1 else f'v{a}'):bad.append((t,a))
    elif p.returncode!=3:bad.append(p.stderr)
  th=[threading.Thread(target=reader) for _ in range(3)];[x.start() for x in th]
  for i in range(2,30):self.sql('update',f"SET title='v{i}', age={i} ALL RECORDS")
  stop.set();[x.join() for x in th];self.assertEqual(bad,[])
 def test_concurrent_contexts_first_committer_wins(self):
  c1,c2=self.ctx(),self.ctx()
  for c in (c1,c2):self.sql('begin','READ WRITE',ctx=c)
  self.sql('update',"SET title='c1' ALL RECORDS",ctx=c1);self.sql('insert',"RECORD other (title) VALUES ('c2')",ctx=c2)
  self.sql('commit','',ctx=c1);p=self.sql('commit','',ctx=c2,status=4);self.assertIn(b'conflict',p.stderr)
  self.sql('rollback','',ctx=c2);self.assertEqual(self.row()[0][0],'c1');self.assertFalse((self.t/'other').exists())
  self.sql('begin','READ WRITE',ctx=c2);self.sql('insert',"RECORD other (title) VALUES ('c2')",ctx=c2);self.sql('commit','',ctx=c2);self.assertTrue((self.t/'other').exists())
 def test_contexts_on_different_tables_do_not_conflict(self):
  o=self.base/'o';o.mkdir();self.sql('create',SCHEMA,cwd=o);c1,c2=self.ctx(),self.ctx()
  for c in (c1,c2):self.sql('begin','READ WRITE',ctx=c)
  self.sql('update',"SET title='c1' ALL RECORDS",ctx=c1);self.sql('insert',f"INTO {q(o)} RECORD x (title) VALUES ('c2')",ctx=c2)
  self.sql('commit','',ctx=c2);self.sql('commit','',ctx=c1);self.assertEqual(self.row()[0][0],'c1');self.assertTrue((o/'x').exists())
 def test_dead_owner_context_cleaned_and_lock_released(self):
  p=subprocess.Popen(['sleep','300']);c=self.sql('context',f'CREATE ON {q(self.base)} OWNER {p.pid}').stdout.decode().strip()
  self.sql('begin','READ WRITE',ctx=c);self.sql('update',"SET title='orphan' ALL RECORDS",ctx=c);p.kill();p.wait()
  # A dead owner's ACTIVE transaction is preserved (recoverable), never applied; live writers proceed.
  p=self.sql('context',f'CLEAN STALE ON {q(self.base)}');self.assertIn(b'preserved recoverable context',p.stdout);self.assertTrue(pathlib.Path(c).exists())
  self.sql('update',"SET title='live' ALL RECORDS");self.assertEqual(self.row()[0][0],'live')
if __name__=='__main__':unittest.main(verbosity=2)
