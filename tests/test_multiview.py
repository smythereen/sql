#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Focused named two-source view checks; private scratch data only."""
import json,os,pathlib,select,shutil,signal,subprocess,tempfile,time,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1];SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def q(s):return "'"+str(s).replace("'","''")+"'"
class MultiView(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-multiview-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name);self.a=self.base/'a';self.b=self.base/'b';self.a.mkdir();self.b.mkdir();self.view=self.base/'view';self.procs=[];self.addCleanup(self.cleanup)
  self.sql('create','TABLE (r DIRECTORY RECORD (title TEXT NOT NULL, age INT64))',cwd=self.a);self.sql('create','TABLE (r DIRECTORY RECORD (amount INT64, label TEXT))',cwd=self.b)
  self.sql('insert',"RECORD same (title,age) VALUES ('alpha',20)",cwd=self.a);self.sql('insert',"RECORD same (amount,label) VALUES (15,'beta')",cwd=self.b)
 def sql(self,verb,text,status=0,cwd=None):
  p=subprocess.run([str(SQL),verb,text],cwd=cwd or self.base,env={k:v for k,v in os.environ.items() if k!='SQL_CONTEXT'},capture_output=True,timeout=5);self.assertEqual(p.returncode,status,(verb,text,p.returncode,p.stdout,p.stderr));return p
 def definition(self):return f"VIEW {q(self.view)} LINKED BRANCHES (leftside AS SELECT title AS name FROM {q(self.a)} WHERE age >= 18 ; rightside AS SELECT amount AS score FROM {q(self.b)} WHERE amount >= 10)"
 def create(self):self.sql('create',self.definition())
 def start(self):
  p=subprocess.Popen([str(SQL),'watch',f'VIEW {q(self.view)} DEBOUNCE 60'],cwd=self.base,env={k:v for k,v in os.environ.items() if k!='SQL_CONTEXT'},stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.procs.append(p);ready,_,_=select.select([p.stderr],[],[],3);self.assertTrue(ready);line=p.stderr.readline();self.assertIn(b'VIEW ready',line,(line,p.poll()));return p
 def stop(self,p):
  if p.poll() is None:p.send_signal(signal.SIGTERM)
  out,err=p.communicate(timeout=3);self.procs.remove(p);self.assertEqual(p.returncode,0,(out,err));self.assertFalse(pathlib.Path('/proc',str(p.pid)).exists());return json.loads(out)
 def cleanup(self):
  for p in self.procs:
   if p.poll() is None:p.terminate()
   try:p.communicate(timeout=2)
   except subprocess.TimeoutExpired:p.kill();p.communicate()
 def wait(self,fn):
  until=time.monotonic()+3
  while time.monotonic()<until:
   try:
    if fn():return
   except FileNotFoundError:pass
   time.sleep(.02)
  self.fail('raw branch membership did not refresh')
 def row(self,branch,name='same'):return self.view/branch/'records'/name
 def test_independent_names_projection_root_and_branch_queries(self):
  self.create();self.assertEqual((self.row('leftside')/'name').read_text(),'alpha');self.assertEqual((self.row('rightside')/'score').read_text(),'15');self.assertFalse((self.row('leftside')/'age').exists());self.assertFalse((self.row('rightside')/'label').exists())
  self.assertEqual(json.loads(self.sql('select','BRANCH leftside name',cwd=self.view).stdout),[['alpha']]);self.assertEqual(json.loads(self.sql('select','*',cwd=self.view/'rightside').stdout),[[15]])
  self.sql('select','BRANCH leftside name FROM '+q(self.b),cwd=self.view,status=2)
  self.sql('select','*',cwd=self.view,status=4);self.sql('select','BRANCH nope *',cwd=self.view,status=4);self.sql('update',"SET name='no' ALL RECORDS",cwd=self.view/'leftside',status=4)
 def test_watcher_refreshes_both_sources_without_select(self):
  self.create();note=self.view/'notes';note.write_text('keep');p=self.start();right=os.readlink(self.view/'rightside/records')
  (self.a/'same/age').write_text('2');self.wait(lambda:not self.row('leftside').exists());self.assertEqual(os.readlink(self.view/'rightside/records'),right)
  (self.b/'same/amount').write_text('1');self.wait(lambda:not self.row('rightside').exists());(self.a/'same/age').write_text('22');self.wait(lambda:self.row('leftside').exists())
  incoming=self.base/'replace';incoming.write_text('19');os.replace(incoming,self.b/'same/amount');self.wait(lambda:self.row('rightside').exists());self.assertEqual((self.row('rightside')/'score').read_text(),'19')
  self.assertEqual(note.read_text(),'keep');self.assertGreater(self.stop(p)['wakeups'],0)
 def test_missing_field_null_append_new_record_and_restart(self):
  self.create();p=self.start();(self.a/'same/title').unlink();self.wait(lambda:self.row('leftside').is_dir() and not (self.row('leftside')/'name').exists());self.assertEqual(json.loads(self.sql('select','*',cwd=self.view/'leftside').stdout),[[None]])
  with (self.b/'same/amount').open('a') as f:f.write('0')
  self.wait(lambda:(self.row('rightside')/'score').read_text()=='150');new=self.a/'new';new.mkdir();(new/'title').write_text('new');(new/'age').write_text('30');self.wait(lambda:self.row('leftside','new').exists());shutil.rmtree(new);self.wait(lambda:not self.row('leftside','new').exists());self.stop(p)
  (self.b/'same/amount').write_text('0');self.assertTrue(self.row('rightside').exists());p=self.start();self.assertFalse(self.row('rightside').exists());self.stop(p)
 def test_bad_names_duplicate_nonempty_and_version_refused(self):
  for name,status in [("'../escape'",2),("'.hidden'",2),("'with space'",2)]:self.sql('create',f'VIEW {q(self.view)} LINKED BRANCHES ({name} AS SELECT title FROM {q(self.a)})',status=status)
  self.sql('create',f'VIEW {q(self.view)} LINKED BRANCHES (dup AS SELECT title FROM {q(self.a)} ; dup AS SELECT amount FROM {q(self.b)})',status=4);self.assertFalse((self.view/'.view').exists())
  self.create();original=(self.view/'.view').read_bytes();bad=bytearray(original);bad[8:12]=(12).to_bytes(4,'little');(self.view/'.view').write_bytes(bad);self.sql('select','BRANCH leftside *',cwd=self.view,status=4);(self.view/'.view').write_bytes(original)
  self.sql('create',self.definition(),status=4);self.assertEqual((self.a/'same/title').read_text(),'alpha')
 def test_same_source_branches_share_watcher_without_collisions(self):
  self.sql('create',f'VIEW {q(self.view)} LINKED BRANCHES (adult AS SELECT title FROM {q(self.a)} WHERE age >= 18 ; child AS SELECT title AS label FROM {q(self.a)} WHERE age < 18)');p=self.start();self.assertTrue(self.row('adult').exists());self.assertFalse(self.row('child').exists());(self.a/'same/age').write_text('5');self.wait(lambda:not self.row('adult').exists() and self.row('child').exists());self.stop(p)
 def test_legacy_branch_field_name_not_reserved_outside_multi_root(self):
  table=self.base/'words';table.mkdir();self.sql('create','TABLE (r DIRECTORY RECORD (branch TEXT))',cwd=table);self.sql('insert',"RECORD a (branch) VALUES ('ordinary')",cwd=table);self.assertEqual(json.loads(self.sql('select','branch',cwd=table).stdout),[['ordinary']])
 def test_root_mem_replay_describe_clone_and_branch_identity_guard(self):
  self.create();tool=pathlib.Path.home()/'bin/sql_viewmem';dump=subprocess.run([str(tool),str(self.view)],capture_output=True,timeout=5);self.assertEqual(dump.returncode,0,dump.stderr);self.assertIn(b'C.version=3',dump.stdout);self.assertIn(b'C.Count=2',dump.stdout)
  script=self.base/'dump';script.write_bytes(dump.stdout);run=subprocess.run(['/bin/sh',str(script)],capture_output=True,timeout=5);self.assertEqual(run.returncode,0,run.stderr)
  changed=subprocess.run([str(tool),str(self.view),'C.Definition','bad'],capture_output=True,timeout=5);self.assertEqual(changed.returncode,4)
  ddl=self.sql('describe','VIEW '+q(self.view)+' AS DDL').stdout.decode().strip();clone=self.base/'clone';self.sql('create',ddl.replace('VIEW LINKED',f'VIEW {q(clone)} LINKED',1));self.assertEqual(json.loads(self.sql('select','BRANCH rightside score',cwd=clone).stdout),[[15]])
  branch=self.view/'leftside';branch.rename(self.view/'saved-left');branch.mkdir();self.sql('select','BRANCH leftside *',cwd=self.view,status=4);self.assertTrue((self.view/'saved-left/.view').exists())
if __name__=='__main__':unittest.main(verbosity=2)
