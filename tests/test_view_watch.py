#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Filesystem-only observations: never SELECT/CHECK to cause watcher refresh."""
import json,os,pathlib,select,shutil,signal,subprocess,tempfile,time,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1];SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def q(s):return "'"+str(s).replace("'","''")+"'"
class ViewWatch(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-view-watch-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name);self.source=self.base/'source';self.source.mkdir();self.view=self.base/'view';self.running=[];self.addCleanup(self.stop_all)
  self.sql('create','TABLE (r DIRECTORY RECORD (title TEXT NOT NULL, age INT64))');self.sql('insert',"RECORD a (title,age) VALUES ('yes',20)")
 def sql(self,verb,text,status=0,cwd=None):
  p=subprocess.run([str(SQL),verb,text],cwd=cwd or self.source,capture_output=True,timeout=6,env={k:v for k,v in os.environ.items() if k!='SQL_CONTEXT'});self.assertEqual(p.returncode,status,(p.returncode,p.stdout,p.stderr));return p
 def create(self,where="title='yes'",projection='title AS label'):
  self.sql('create',f'VIEW {q(self.view)} LINKED AS SELECT {projection} WHERE {where}')
 def start(self):
  p=subprocess.Popen([str(SQL),'watch',f'VIEW {q(self.view)} DEBOUNCE 60'],cwd=self.base,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={k:v for k,v in os.environ.items() if k!='SQL_CONTEXT'});self.running.append(p)
  ready,_,_=select.select([p.stderr],[],[],3);self.assertTrue(ready,'watcher startup timeout');line=p.stderr.readline();self.assertIn(b'VIEW ready',line,(line,p.poll()));return p
 def stop(self,p):
  if p.poll() is None:p.send_signal(signal.SIGTERM)
  out,err=p.communicate(timeout=4);self.assertEqual(p.returncode,0,(out,err));self.assertFalse(pathlib.Path('/proc',str(p.pid)).exists());self.running.remove(p);return json.loads(out)
 def stop_all(self):
  for p in self.running:
   if p.poll() is None:p.terminate()
   try:p.communicate(timeout=3)
   except subprocess.TimeoutExpired:p.kill();p.communicate()
 def wait(self,condition):
  deadline=time.monotonic()+3
  while time.monotonic()<deadline:
   try:
    if condition():return
   except FileNotFoundError:pass
   time.sleep(.02)
  self.fail('raw filesystem did not reconcile within 3 seconds')
 def record(self,name='a'):return self.view/'records'/name
 def test_overwrite_append_and_write_through_field_link(self):
  self.create();p=self.start();notes=self.view/'notes';notes.write_text('preserve')
  incoming=self.base/'incoming';incoming.write_text('no');subprocess.run(['/bin/cp',str(incoming),str(self.record()/'label')],check=True);self.assertEqual((self.source/'a/title').read_text(),'no');self.wait(lambda:not self.record().exists())
  (self.source/'a/title').write_text('yes');self.wait(lambda:self.record().exists())
  with (self.record()/'label').open('a') as f:f.write('!')
  self.assertEqual((self.source/'a/title').read_text(),'yes!');self.wait(lambda:not self.record().exists())
  (self.source/'a/title').write_text('yes');self.wait(lambda:self.record().exists())
  (self.source/'a/title').write_text('no');self.wait(lambda:not self.record().exists())
  (self.source/'a/title').write_text('yes');self.wait(lambda:self.record().exists());self.assertEqual(notes.read_text(),'preserve');self.assertGreater(self.stop(p)['wakeups'],0)
 def test_removed_required_field_becomes_null_and_check_still_flags_it(self):
  self.create(where='title IS NULL');p=self.start();self.assertFalse(self.record().exists());(self.source/'a/title').unlink()
  self.wait(lambda:self.record().is_dir());self.assertFalse((self.record()/'label').exists());self.assertFalse((self.source/'a/title').exists())
  self.assertEqual(json.loads(self.sql('select','*',cwd=self.view).stdout),[[None]])
  self.sql('check','TABLE COUNTS',status=4);(self.source/'a/title').write_text('restored');self.wait(lambda:not self.record().exists());self.stop(p)
 def test_new_recursive_record_atomic_replacement_and_record_delete(self):
  self.create();p=self.start();row=self.source/'b';row.mkdir();(row/'title').write_text('yes');(row/'age').write_text('25');self.wait(lambda:self.record('b').is_dir())
  staged=self.base/'replacement';staged.write_text('no');os.replace(staged,row/'title');self.wait(lambda:not self.record('b').exists())
  staged.write_text('yes');os.replace(staged,row/'title');self.wait(lambda:self.record('b').exists())
  shutil.rmtree(row);self.wait(lambda:not self.record('b').exists());self.stop(p)
 def test_restart_rescans_offline_changes(self):
  self.create();p=self.start();self.stop(p);(self.source/'a/title').write_text('offline');self.assertTrue(self.record().exists());p=self.start();self.assertFalse(self.record().exists());self.stop(p)
 def test_append_numeric_value_and_invalid_type_is_not_repaired(self):
  self.create(where='age >= 200',projection='age');p=self.start();self.assertFalse(self.record().exists())
  with (self.source/'a/age').open('a') as f:f.write('0')
  self.wait(lambda:self.record().exists());self.assertEqual((self.record()/'age').read_text(),'200')
  with (self.source/'a/age').open('a') as f:f.write('x')
  self.sql('select','age',status=4);time.sleep(.2);self.assertEqual((self.source/'a/age').read_text(),'200x');summary=self.stop(p);self.assertGreater(summary['failures'],0);self.assertEqual(summary['last_status'],4)
 def test_duration_stop_and_single_watcher_lease(self):
  self.create();p=self.start();other=self.sql('watch',f'VIEW {q(self.view)} DURATION 100',status=4,cwd=self.base);self.assertIn(b'already watched',other.stderr);self.stop(p)
  finished=self.sql('watch',f'VIEW {q(self.view)} DURATION 120',cwd=self.base);self.assertGreater(json.loads(finished.stdout)['refreshes'],0)
 def test_periodic_reconciliation_without_source_event(self):
  self.create();p=self.start();tool=pathlib.Path.home()/'bin/sql_viewmem'
  changed=subprocess.run([str(tool),str(self.view),'C.Query',"title AS renamed FROM "+q(self.source)+" WHERE title='yes'"],cwd=self.base,capture_output=True,timeout=4);self.assertEqual(changed.returncode,0,changed.stderr)
  self.wait(lambda:(self.record()/'renamed').is_symlink());self.assertFalse((self.record()/'label').exists());self.stop(p)
 def test_unlink_view_link_does_not_delete_source(self):
  self.create();p=self.start();(self.record()/'label').unlink();self.assertEqual((self.source/'a/title').read_text(),'yes');self.stop(p)
 def test_symlink_loop_not_followed_and_source_replacement_fails_closed(self):
  self.create();p=self.start();(self.source/'loop').symlink_to(self.source,target_is_directory=True);time.sleep(.15);(self.source/'loop').unlink();self.assertEqual((self.source/'a/title').read_text(),'yes')
  old=self.base/'old';self.source.rename(old);self.source.mkdir();out,err=p.communicate(timeout=3);self.running.remove(p);self.assertEqual(p.returncode,4,(out,err));self.assertIn(b'no automatic retargeting',err);self.assertEqual((old/'a/title').read_text(),'yes')
if __name__=='__main__':unittest.main(verbosity=2)
