#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Transactional multi-view (BRANCH) reads and autocommit context
persistence.  /tmp scratch fixtures only."""
import json,os,pathlib,subprocess,tempfile,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1];SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def q(s):return "'"+str(s).replace("'","''")+"'"
class Base(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-txr-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name);self.t=self.base/'t';self.t.mkdir()
  self.env={k:v for k,v in os.environ.items() if k not in('SQL_CONTEXT','DATABASE_DIR')};self.env['DATABASE_DIR']=str(self.base)
  self.sql('create','TABLE (r DIRECTORY RECORD (title TEXT, n INT64))')
  for r,n in (('a',1),('b',2)):self.sql('insert',f"RECORD {r} (title,n) VALUES ('{r}',{n})")
 def sql(self,verb,text='',status=0,cwd=None,ctx=None):
  env=dict(self.env)
  if ctx:env['SQL_CONTEXT']=ctx
  p=subprocess.run([str(SQL),verb,text],cwd=cwd or self.t,env=env,capture_output=True,timeout=20);self.assertEqual(p.returncode,status,(verb,text,p.returncode,p.stdout,p.stderr))
  return p
 def js(self,verb,text,**k):return json.loads(self.sql(verb,text,**k).stdout)
 def ctx(self):
  # A dedicated long-lived owner: this test process already owns the
  # autocommit context created by setUp's view DDL at the same root.
  o=subprocess.Popen(['sleep','600']);self.addCleanup(o.wait);self.addCleanup(o.kill)
  return self.sql('context',f'CREATE ON {q(self.base)} OWNER {o.pid}').stdout.decode().strip()
class BranchReads(Base):
 def setUp(self):
  super().setUp();self.mv=self.base/'mv'
  self.sql('create',f"VIEW {q(self.mv)} LINKED BRANCHES (low AS SELECT title FROM {q(self.t)} WHERE n < 2 ; high AS SELECT title FROM {q(self.t)} WHERE n >= 2)",cwd=self.base)
 def branch(self,b,**k):return sorted(self.js('select',f'BRANCH {b} title',cwd=self.mv,**k))
 def test_branch_read_sees_staged_writes_without_publishing(self):
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.sql('update',"SET n=0 WHERE record='b'",ctx=c)
  self.assertEqual(self.branch('low',ctx=c),[['a'],['b']]);self.assertEqual(self.branch('high',ctx=c),[])
  self.assertEqual(self.branch('low'),[['a']]);self.assertEqual(sorted(p.name for p in (self.mv/'low'/'records').iterdir()),['a'])
  self.sql('rollback','',ctx=c);self.assertEqual(self.branch('high'),[['b']])
 def test_branch_read_after_commit(self):
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.sql('update',"SET n=0 WHERE record='b'",ctx=c);self.sql('commit','',ctx=c)
  self.assertEqual(self.branch('low'),[['a'],['b']])
 def test_read_only_transaction_branch_read(self):
  c=self.ctx();self.sql('begin','READ ONLY',ctx=c);self.assertEqual(self.branch('high',ctx=c),[['b']]);self.sql('commit','',ctx=c)
 def test_branch_ddl_in_transaction_still_refused(self):
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.sql('drop',f'VIEW {q(self.mv)}',ctx=c,cwd=self.base,status=7);self.sql('rollback','',ctx=c);self.assertTrue((self.mv/'.view').exists())
class AutocommitPersistence(Base):
 def contexts(self):return sorted((self.t/'.context').iterdir()) if (self.t/'.context').exists() else []
 def test_reads_do_not_provision(self):
  import shutil;shutil.rmtree(self.t/'.context');self.sql('select','title');self.sql('check','TABLE');self.assertEqual(self.contexts(),[])
 def test_write_retains_command_and_hardlinked_bytes(self):
  self.sql('insert',"RECORD c (title,n) VALUES ('c',3)");ctx=self.contexts()[-1]
  seqs=sorted(int(p.name) for p in (ctx/'commands').iterdir());last=seqs[-1]
  self.assertTrue((ctx/'commands'/str(last)/'.changes').stat().st_size>0)
  # Retained bytes are an independent copy: in-place edits of the live file
  # cannot rewrite history (apply copies the staged payload into place).
  kept=ctx/'tables'/f'autocommit-{last}'/'c'/'title';self.assertNotEqual(kept.stat().st_ino,(self.t/'c'/'title').stat().st_ino);self.assertEqual(kept.read_text(),'c')
  (self.t/'c'/'title').write_text('edited in place');self.assertEqual(kept.read_text(),'c')
  self.assertEqual((ctx/'commands'/str(last)/'.source').read_text().splitlines()[0],'SQL_AUTOCOMMIT 1')
 def test_history_survives_later_update(self):
  self.sql('update',"SET title='v1' WHERE record='a'");self.sql('update',"SET title='v2' WHERE record='a'")
  vals=sorted(p.read_text() for p in (self.t/'.context').rglob('tables/autocommit-*/a/title'))
  self.assertIn('v1',vals);self.assertIn('v2',vals);self.assertEqual((self.t/'a'/'title').read_text(),'v2')
 def test_validate_only_does_not_provision(self):
  import shutil;shutil.rmtree(self.t/'.context');self.sql('drop','TABLE VALIDATE ONLY');self.assertEqual(self.contexts(),[])
if __name__=='__main__':unittest.main()
