#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Focused single-source linked-view tests. Only private scratch tables are used."""
import json,os,pathlib,subprocess,tempfile,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1]
SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def q(s):return "'"+str(s).replace("'","''")+"'"
class LinkedViews(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-linked-view-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name);self.source=self.base/'source';self.source.mkdir();self.view=self.base/'view'
  self.call('create','TABLE (r DIRECTORY RECORD (title TEXT [0-1], age INT64, secret TEXT [0-1]))')
 def call(self,verb,text='',status=0,cwd=None):
  env={k:v for k,v in os.environ.items() if k!='SQL_CONTEXT'}
  p=subprocess.run([str(SQL),verb,text],cwd=cwd or self.source,env=env,capture_output=True,timeout=8)
  self.assertEqual(p.returncode,status,(verb,text,p.returncode,p.stdout,p.stderr));return p
 def insert(self,name,title='first',age=20):self.call('insert',f'RECORD {q(name)} (title,age,secret) VALUES ({q(title)},{age},\'hidden\')')
 def createview(self,projection='title AS label',suffix='WHERE age >= 18'):
  self.call('create',f'VIEW {q(self.view)} LINKED AS SELECT {projection} {suffix}')
 def rows(self):return json.loads(self.call('select','*',cwd=self.view).stdout)
 def test_initial_field_links_projection_cwd_and_source_bytes(self):
  self.insert('a');self.insert('b',age=10);self.createview()
  self.assertTrue((self.view/'records').is_symlink());link=self.view/'records/a/label';self.assertTrue(link.is_symlink());self.assertEqual(link.resolve(),self.source/'a/title');self.assertEqual(link.read_text(),'first')
  self.assertEqual({p.name for p in (self.view/'records/a').iterdir()},{'label'});self.assertEqual(self.rows(),[['first']]);self.assertFalse((self.view/'records/b').exists())
  self.call('select','secret',cwd=self.view,status=2)
 def test_membership_insert_enters_exits_filter_update_and_delete(self):
  self.insert('a');self.createview();self.insert('b',age=21);self.assertFalse((self.view/'records/b').exists())
  self.assertEqual(len(self.rows()),2);self.assertTrue((self.view/'records/b/label').is_symlink())
  self.call('update',"SET age=5 WHERE record='a'");self.assertTrue((self.view/'records/a').exists());self.assertEqual(self.rows(),[['first']]);self.assertFalse((self.view/'records/a').exists())
  self.call('update',"SET age=30 WHERE record='a'");self.assertEqual(len(self.rows()),2);self.assertTrue((self.view/'records/a').exists())
  self.call('delete',"WHERE record='b'");self.assertEqual(len(self.rows()),1);self.assertFalse((self.view/'records/b').exists())
 def test_source_field_replacement_bytes_and_row_rename(self):
  self.insert('a');self.createview();link=self.view/'records/a/label';self.call('update',"SET title='replacement' ALL RECORDS");self.assertEqual(link.read_text(),'replacement');self.assertEqual(self.rows(),[['replacement']])
  self.call('alter',"TABLE RENAME RECORD 'a' TO 'renamed'");self.assertEqual(self.rows(),[['replacement']]);self.assertFalse((self.view/'records/a').exists());self.assertEqual((self.view/'records/renamed/label').read_text(),'replacement')
 def test_readonly_mutation_paths_and_unrelated_entries_preserved(self):
  self.insert('a');self.createview();note=self.view/'notes.txt';note.write_text('keep me')
  for verb,text in [('insert',"RECORD nope (label) VALUES ('no')"),('update',"SET label='no' ALL RECORDS"),('delete','ALL RECORDS'),('link',"FIELD label TO 'a/title' FROM SOURCE . ALL RECORDS"),('unlink','FIELD label ALL RECORDS')]:self.call(verb,text,cwd=self.view,status=4)
  self.call('update',"SET age=8 ALL RECORDS");self.assertEqual(self.rows(),[]);self.assertEqual(note.read_text(),'keep me');self.assertEqual((self.source/'a/title').read_text(),'first')
 def test_restart_refresh_definition_and_unmanaged_generation_content(self):
  self.insert('a');self.createview();old=(self.view/'records').resolve();(old/'user-note').write_text('preserve')
  self.insert('b');self.assertEqual(len(self.rows()),2);self.assertNotEqual((self.view/'records').resolve(),old);self.assertEqual((old/'user-note').read_text(),'preserve')
  ddl=self.call('describe','VIEW '+q(self.view)+' AS DDL').stdout.decode();self.assertIn('VIEW LINKED AS SELECT',ddl);self.assertEqual(len(self.rows()),2)
  target=os.readlink(self.view/'records');self.rows();self.assertEqual(os.readlink(self.view/'records'),target,'unchanged reads should reuse snapshot')
 def test_foreign_records_collision_not_overwritten(self):
  self.insert('a');self.createview();(self.view/'records').unlink();(self.view/'records').write_text('unmanaged')
  self.call('select','*',cwd=self.view,status=4);self.assertEqual((self.view/'records').read_text(),'unmanaged')
 def test_source_identity_replacement_refused_and_hidden_field_not_exposed(self):
  self.insert('a');self.createview();saved=self.base/'old-source';self.source.rename(saved);self.source.mkdir();self.call('create','TABLE (r DIRECTORY RECORD (title TEXT, age INT64, secret TEXT))');self.insert('a','imposter')
  self.call('select','*',cwd=self.view,status=4);self.assertEqual((saved/'a/title').read_text(),'first')
 def test_computed_collection_and_view_source_refused_without_definition(self):
  self.insert('a');self.call('create',f'VIEW {q(self.view)} LINKED AS SELECT COUNT(title)',status=7);self.assertFalse((self.view/'.view').exists())
  saved=self.base/'saved';self.call('create',f'VIEW {q(saved)} AS SELECT title');self.call('create',f'VIEW {q(self.view)} LINKED AS SELECT title FROM {q(saved)}',status=7);self.assertFalse((self.view/'.view').exists())
 def test_optional_field_absence_and_collection_refusal(self):
  self.call('insert',"RECORD absent (age) VALUES (20)");self.createview();self.assertEqual(self.rows(),[[None]]);self.assertTrue((self.view/'records/absent').is_dir());self.assertFalse((self.view/'records/absent/label').exists())
  other=self.base/'collections';other.mkdir();self.call('create','TABLE (r DIRECTORY RECORD (parts TEXT [0-2]))',cwd=other)
  rejected=self.base/'rejected';self.call('create',f'VIEW {q(rejected)} LINKED AS SELECT parts',cwd=other,status=7);self.assertFalse((rejected/'.view').exists())
 def test_check_refresh_and_create_nonempty_preserves_entries(self):
  self.insert('a');self.createview();self.insert('b');self.call('check','VIEW '+q(self.view));self.assertTrue((self.view/'records/b/label').is_symlink())
  foreign=self.base/'foreign';foreign.mkdir();note=foreign/'precious';note.write_text('keep');self.call('create',f'VIEW {q(foreign)} LINKED AS SELECT title',status=4);self.assertEqual(note.read_text(),'keep');self.assertFalse((foreign/'.view').exists())
 def test_saved_view_and_linked_mem_decoder_query_edit(self):
  self.insert('a');self.createview();tool=pathlib.Path.home()/'bin/sql_viewmem';dump=subprocess.run([str(tool),str(self.view)],capture_output=True,timeout=8);self.assertEqual(dump.returncode,0,dump.stderr);self.assertIn(b'C.version=2',dump.stdout);self.assertIn(b'C.reserved=1',dump.stdout)
  update='title AS renamed FROM '+q(self.source)+' WHERE age < 18';p=subprocess.run([str(tool),str(self.view),'C.Query',update],cwd=self.source,capture_output=True,timeout=8);self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.rows(),[])
  self.call('update','SET age=1 ALL RECORDS');self.assertEqual(self.rows(),[['first']]);self.assertTrue((self.view/'records/a/renamed').is_symlink());self.assertFalse((self.view/'records/a/label').exists())
  saved=self.base/'saved';self.call('create',f'VIEW {q(saved)} AS SELECT COUNT(title) AS total');self.assertEqual(json.loads(self.call('select','*',cwd=saved).stdout),[[1]])
if __name__=='__main__':unittest.main(verbosity=2)
