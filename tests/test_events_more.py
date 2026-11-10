#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Item 8: event kinds (record INSERT/DELETE/RENAME), trigger WHERE, persisted
skipped accounting, cross-table event fanout (incl. crash re-drive and
transactions), watch overflow rescans, and linked-generation GC.
All data is private /tmp scratch; handlers are local scripts."""
import json,os,pathlib,subprocess,tempfile,time,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1]
SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def q(s):return "'"+str(s).replace("'","''")+"'"
SCHEMA="TABLE (r DIRECTORY RECORD (title TEXT, age INT64 [0-1])) LINKS INTERNAL"
class Base(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-events-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name)
  self.env={k:v for k,v in os.environ.items() if k not in('SQL_CONTEXT','DATABASE_DIR','SQL_TEST_CRASH','SQL_TEST_WATCH_OVERFLOW')};self.env['DATABASE_DIR']=str(self.base)
  self.t=self.base/'t';self.t.mkdir();self.sql('create',SCHEMA)
  self.log=self.base/'log';self.handler=self.base/'handler'
  self.handler.write_text("#!/usr/bin/python3\nimport json,sys,pathlib\ne=json.load(sys.stdin)\nwith open(sys.argv[1],'a') as f: f.write(json.dumps(e)+'\\n')\n");self.handler.chmod(0o700)
 def sql(self,verb,text='',status=0,cwd=None,env=None,ctx=None):
  e=dict(self.env)
  if env:e.update(env)
  if ctx:e['SQL_CONTEXT']=ctx
  p=subprocess.run([str(SQL),verb,text],cwd=cwd or self.t,env=e,capture_output=True,timeout=30)
  self.assertEqual(p.returncode,status,(verb,text,p.returncode,p.stdout,p.stderr));return p
 def trig(self,name,after,tail='',cwd=None,status=0):
  return self.sql('trigger',f'CREATE {name} AFTER {after} {tail} EXECUTE {q(self.handler)} ARGUMENTS ({q(self.log)}) ENABLED',cwd=cwd,status=status)
 def watch(self,cwd=None,env=None):return json.loads(self.sql('watch','FOR ALL ONCE',cwd=cwd,env=env).stdout)
 def rows(self):return [json.loads(l) for l in self.log.read_text().splitlines()] if self.log.exists() else []
 def show(self,cwd=None):return {d['name']:d for d in json.loads(self.sql('trigger','SHOW',cwd=cwd).stdout)}
 def events(self,root):
  out=[]
  for f in (root/'.sql'/'events').iterdir():
   b=f.read_bytes();out.append(json.loads(b[b.index(b'{"transaction"'):].decode()))
  return sorted(out,key=lambda e:e['generation'])
class Kinds(Base):
 def test_record_insert_has_record_level_entry_after_fields(self):
  self.sql('insert',"RECORD a (title) VALUES ('x')");ev=self.events(self.t)[-1]['logical']
  self.assertEqual(ev[0]['field'],'title');self.assertEqual(ev[-1],{'event':ev[-1]['event'],'kind':1,'record':'a','field':'','path':'a'})
 def test_record_delete_emits_record_and_member_deletes(self):
  self.sql('insert',"RECORD a (title,age) VALUES ('x',3)");self.sql('delete',"WHERE record='a'");ev=self.events(self.t)[-1]['logical']
  self.assertEqual({(x['field'],x['kind']) for x in ev},{('title',4),('age',4),('',4)})
 def test_record_rename_emits_rename_kind(self):
  self.sql('insert',"RECORD a (title) VALUES ('x')");self.sql('alter',"TABLE RENAME RECORD a TO b");ev=self.events(self.t)[-1]['logical']
  self.assertIn({'event':ev[0]['event'],'kind':32,'record':'b','field':'title','path':'b/title'},[dict(x,event=ev[0]['event']) for x in ev])
  self.assertTrue(any(x['field']=='' and x['kind']==32 and x['path']=='b' for x in ev))
 def test_rename_trigger_and_commit_includes_rename(self):
  self.trig('ren','RENAME');self.trig('all','COMMIT');self.sql('insert',"RECORD a (title) VALUES ('x')");self.sql('alter',"TABLE RENAME RECORD a TO b")
  r=self.watch();self.assertEqual(r['delivered'],3);s=self.show();self.assertEqual(s['ren']['delivered'],1);self.assertEqual(s['ren']['skipped'],1);self.assertEqual(s['all']['delivered'],2)
 def test_delete_trigger_fires_on_record_delete(self):
  self.trig('del','DELETE');self.sql('insert',"RECORD a (title) VALUES ('x')");self.sql('delete',"WHERE record='a'")
  self.assertEqual(self.watch()['delivered'],1);self.assertEqual(self.rows()[0]['logical'][-1]['kind'],4)
 def test_unknown_kind_refused(self):
  self.trig('bad','TRUNCATE',status=2)
class Where(Base):
 def test_where_filters_on_post_image_and_counts_skipped(self):
  # WHERE reads the record's committed state when the watcher delivers.
  self.trig('adult','INSERT,UPDATE',"WHERE age >= 18")
  self.sql('insert',"RECORD a (title,age) VALUES ('kid',5)");r1=self.watch()
  self.sql('insert',"RECORD b (title,age) VALUES ('grown',30)");self.sql('update',"SET age=20 WHERE record='a'");r2=self.watch()
  self.assertEqual((r1['delivered'],r1['skipped']),(0,1));self.assertEqual((r2['delivered'],r2['skipped']),(2,0))
  self.assertEqual([e['logical'][0]['record'] for e in self.rows()],['b','a'])
  s=self.show()['adult'];self.assertEqual((s['delivered'],s['skipped']),(2,1));self.assertEqual(s['where'],'age >= 18')
 def test_skipped_counter_persists_across_watch_runs(self):
  self.trig('never','COMMIT',"WHERE title = 'nothing'")
  for i in range(3):self.sql('insert',f"RECORD r{i} (title) VALUES ('x')");self.watch()
  self.assertEqual(self.show()['never']['skipped'],3)
  self.sql('trigger','DROP never');self.trig('never','COMMIT',"WHERE title = 'nothing'");self.assertEqual(self.show()['never']['skipped'],0)
 def test_event_pseudo_fields(self):
  self.trig('t','COMMIT',"WHERE event_field = 'age' AND event_kind = 'UPDATE'")
  self.sql('insert',"RECORD a (title,age) VALUES ('x',1)");self.sql('update',"SET title='y' ALL RECORDS");self.sql('update',"SET age=2 ALL RECORDS")
  r=self.watch();self.assertEqual((r['delivered'],r['skipped']),(1,2))
 def test_deleted_record_reads_null(self):
  self.trig('gone','DELETE',"WHERE title IS NULL AND event_record = 'a'")
  self.sql('insert',"RECORD a (title) VALUES ('x')");self.sql('insert',"RECORD b (title) VALUES ('x')");self.sql('delete','ALL RECORDS')
  self.assertEqual(self.watch()['delivered'],1)
 def test_where_with_of_and_canonical_definition(self):
  self.trig('t','UPDATE',"OF (title) WHERE title = 'it''s'")
  self.sql('insert',"RECORD a (title) VALUES ('x')");self.sql('update',"SET title='it''s' ALL RECORDS");self.assertEqual(self.watch()['delivered'],1)
  dump=subprocess.run([os.environ.get('SQL_TEST_TRGMEM_EXECUTABLE',str(pathlib.Path.home()/'bin/sql_trgmem')),str(self.t)],cwd=self.t,env=self.env,capture_output=True,text=True,timeout=10)
  self.assertEqual(dump.returncode,0,dump.stderr);self.assertIn('WHERE title = ',dump.stdout);self.assertIn('Skipped=1',dump.stdout)
  self.assertEqual(self.show()['t']['where'],"title = 'it''s'")
 def test_where_validated_at_create(self):
  self.sql('trigger','INIT');self.trig('bad','COMMIT',"WHERE nosuch = 1",status=2);self.assertEqual(self.show(),{})
  self.trig('bad','COMMIT',"WHERE",status=2)
class Fanout(Base):
 def setUp(self):
  super().setUp();self.s=self.base/'s';self.s.mkdir();self.sql('create',SCHEMA,cwd=self.s);self.sql('insert',"RECORD a (title) VALUES ('src')",cwd=self.s)
  for r in 'bc':self.sql('insert',f"RECORD {r} (title) VALUES ('d')")
  self.sql('link',f"FIELD title TO 'a/title' FROM SOURCE {q(self.s)} ALL RECORDS")
 def notices(self):return [e for e in self.events(self.t) if any(p['operation']=='N' for p in e['physical'])]
 def test_owner_update_notifies_consumer_trigger(self):
  self.trig('t','UPDATE',"OF (title)");self.sql('update',"SET title='new' ALL RECORDS",cwd=self.s)
  n=self.notices();self.assertEqual(len(n),1);self.assertEqual(sorted((x['record'],x['kind']) for x in n[0]['logical']),[('b',2),('c',2)])
  self.assertEqual(self.watch()['delivered'],1);self.assertEqual(list((self.s/'.sql'/'fanout').iterdir()),[]);self.assertEqual(list((self.t/'.sql'/'fanin').iterdir()),[])
 def test_where_sees_new_shared_value(self):
  self.trig('t','UPDATE',"WHERE title = 'new'");self.sql('update',"SET title='new' ALL RECORDS",cwd=self.s);self.assertEqual(self.watch()['delivered'],1)
 def test_consumer_update_notifies_other_consumer_and_itself_once(self):
  e2=self.base/'e2';e2.mkdir();self.sql('create',SCHEMA,cwd=e2);self.sql('insert',"RECORD z (title) VALUES ('q')",cwd=e2)
  self.sql('link',f"FIELD title TO 'a/title' FROM SOURCE {q(self.s)} ALL RECORDS",cwd=e2)
  before=len(self.events(self.t));self.sql('update',"SET title='via e2' ALL RECORDS",cwd=e2)
  self.assertEqual(len(self.notices()),1);self.assertEqual(len([e for e in self.events(e2) if any(p['operation']=='N' for p in e['physical'])]),1)
  self.assertEqual(len(self.events(self.t)),before+1)
 def test_crash_before_drain_redriven_by_owner_watch(self):
  self.sql('update',"SET title='crash' ALL RECORDS",cwd=self.s,env={'SQL_TEST_CRASH':'fanout-before-drain'},status=96)
  self.assertEqual(len(list((self.s/'.sql'/'fanout').iterdir())),1);self.assertEqual(self.notices(),[])
  self.sql('trigger','INIT',cwd=self.s);self.watch(cwd=self.s);self.assertEqual(len(self.notices()),1);self.assertEqual(list((self.s/'.sql'/'fanout').iterdir()),[])
  self.watch(cwd=self.s);self.assertEqual(len(self.notices()),1)
 def test_crash_after_notice_never_duplicates(self):
  e2=self.base/'e2';e2.mkdir();self.sql('create',SCHEMA,cwd=e2);self.sql('insert',"RECORD z (title) VALUES ('q')",cwd=e2)
  self.sql('link',f"FIELD title TO 'a/title' FROM SOURCE {q(self.s)} ALL RECORDS",cwd=e2)
  self.sql('update',"SET title='half' ALL RECORDS",cwd=self.s,env={'SQL_TEST_CRASH':'fanout-after-notice'},status=97)
  self.sql('trigger','INIT',cwd=self.s);self.watch(cwd=self.s)  # owner WATCH re-drives every intention
  for root in (self.t,e2):self.assertEqual(len([e for e in self.events(root) if any(p['operation']=='N' for p in e['physical'])]),1,root)
  self.assertEqual(list((self.s/'.sql'/'fanout').iterdir()),[])
 def test_transaction_commit_notifies_only_after_commit(self):
  owner=subprocess.Popen(['sleep','60']);self.addCleanup(owner.kill)
  c=self.sql('context',f'CREATE ON {q(self.base)} OWNER {owner.pid}').stdout.decode().strip()
  self.sql('begin','READ WRITE',ctx=c,cwd=self.s);self.sql('update',"SET title='txn' ALL RECORDS",ctx=c,cwd=self.s)
  self.assertEqual(self.notices(),[]);self.sql('commit','',ctx=c,cwd=self.s);self.assertEqual(len(self.notices()),1)
  self.assertEqual(json.loads(self.sql('select','title').stdout),[['txn'],['txn']])
 def test_rollback_notifies_nothing(self):
  owner=subprocess.Popen(['sleep','60']);self.addCleanup(owner.kill)
  c=self.sql('context',f'CREATE ON {q(self.base)} OWNER {owner.pid}').stdout.decode().strip()
  self.sql('begin','READ WRITE',ctx=c,cwd=self.s);self.sql('update',"SET title='no' ALL RECORDS",ctx=c,cwd=self.s);self.sql('rollback','',ctx=c,cwd=self.s)
  self.assertEqual(self.notices(),[])
class Overflow(Base):
 def test_overflow_rescan_delivers_every_event_once(self):
  self.trig('t','COMMIT')
  for i in range(20):self.sql('insert',f"RECORD r{i} (title) VALUES ('x')")
  r=self.watch(env={'SQL_TEST_WATCH_OVERFLOW':'1'});self.assertEqual(r['delivered'],20);self.assertGreaterEqual(r['overflows'],1)
  r=self.watch(env={'SQL_TEST_WATCH_OVERFLOW':'1'});self.assertEqual(r['delivered'],0);self.assertEqual(len(self.rows()),20)
  self.assertEqual(len({e['transaction'] for e in self.rows()}),20)
class LinkedGC(Base):
 def setUp(self):
  super().setUp();self.v=self.base/'v';self.sql('insert',"RECORD a (title,age) VALUES ('x',20)")
  self.sql('create',f"VIEW {q(self.v)} LINKED AS SELECT title AS label WHERE age >= 18")
 def gens(self):return sorted(p.name for p in (self.v/'.linked').iterdir() if p.is_dir())
 def republish(self,n):
  for i in range(n):self.sql('insert',f"RECORD g{i} (title,age) VALUES ('y',30)");self.sql('select','*',cwd=self.v)
 def test_prune_keeps_current_and_requested(self):
  self.republish(4);self.assertGreaterEqual(len(self.gens()),5);cur=os.readlink(self.v/'records')[8:]
  r=json.loads(self.sql('alter',f"VIEW {q(self.v)} PRUNE GENERATIONS KEEP 1",cwd=self.base).stdout);self.assertEqual(r['views'],1);self.assertEqual(r['kept'],1)
  self.assertEqual(len(self.gens()),2);self.assertIn(cur,self.gens());self.assertEqual(len(json.loads(self.sql('select','*',cwd=self.v).stdout)),5)
  r=json.loads(self.sql('alter','VIEW PRUNE GENERATIONS',cwd=self.v).stdout);self.assertEqual(self.gens(),[cur]);self.assertEqual(r['removed'],1)
 def test_unmanaged_content_preserved(self):
  old=(self.v/'records').resolve();(old/'note').write_text('keep');self.republish(1)
  r=json.loads(self.sql('alter',f"VIEW {q(self.v)} PRUNE GENERATIONS",cwd=self.base).stdout);self.assertEqual(r['kept'],1);self.assertEqual((old/'note').read_text(),'keep')
 def test_automatic_gc_respects_grace(self):
  self.republish(10);self.assertGreaterEqual(len(self.gens()),11)  # all younger than the 60 s grace
 def test_not_linked_and_transaction_refused(self):
  self.sql('alter',f"VIEW {q(self.t)} PRUNE GENERATIONS",cwd=self.base,status=4)
  owner=subprocess.Popen(['sleep','60']);self.addCleanup(owner.kill)
  c=self.sql('context',f'CREATE ON {q(self.base)} OWNER {owner.pid}').stdout.decode().strip();self.sql('begin','READ WRITE',ctx=c)
  self.sql('alter',f"VIEW {q(self.v)} PRUNE GENERATIONS",cwd=self.base,ctx=c,status=7);self.sql('rollback','',ctx=c)
  self.sql('alter',f"VIEW {q(self.v)} PRUNE GENERATIONS KEEP x",cwd=self.base,status=2)
if __name__=='__main__':unittest.main(verbosity=2)
