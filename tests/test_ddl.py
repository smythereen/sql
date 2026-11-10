#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""RETURNING, dependency registry, ALTER, DROP INCLUDING DATA and
transactional DDL.  Private /tmp scratch fixtures only."""
import json,os,pathlib,subprocess,tempfile,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1];SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def q(s):return "'"+str(s).replace("'","''")+"'"
class Base(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-ddl-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name);self.t=self.base/'t';self.t.mkdir()
  self.env={k:v for k,v in os.environ.items() if k not in('SQL_CONTEXT','DATABASE_DIR')};self.env['DATABASE_DIR']=str(self.base)
  self.sql('create','TABLE (g DIRECTORY (r DIRECTORY RECORD (title TEXT, n INT64 [0-1])))')
  self.sql('insert',"RECORD 'x/a' (title,n) VALUES ('alpha',1)");self.sql('insert',"RECORD 'x/b' (title) VALUES ('beta')")
 def sql(self,verb,text='',status=0,cwd=None,ctx=None):
  env=dict(self.env)
  if ctx:env['SQL_CONTEXT']=ctx
  p=subprocess.run([str(SQL),verb,text],cwd=cwd or self.t,env=env,capture_output=True,timeout=15);self.assertEqual(p.returncode,status,(verb,text,p.returncode,p.stdout,p.stderr))
  if status:self.assertEqual(p.stdout,b'')
  return p
 def js(self,verb,text,**k):return json.loads(self.sql(verb,text,**k).stdout)
 def sel(self,text,**k):return self.js('select',text,**k)
 def ctx(self):
  # Owner is this long-lived test process so the context outlives each CLI call.
  return self.sql('context',f'CREATE ON {q(self.base)} OWNER {os.getpid()}').stdout.decode().strip()
class Returning(Base):
 def test_insert_returning_post_image_and_defaults(self):
  self.assertEqual(self.js('insert',"RECORD 'x/c' (title,n) VALUES ('gamma',007) RETURNING record, title, n"),[['x/c','gamma',7]])
 def test_update_returning_only_matched_rows_star(self):
  self.assertEqual(self.js('update',"SET title='A' WHERE n = 1 RETURNING *"),[['A',1]])
  self.assertEqual(sorted(self.sel('title')),[['A'],['beta']])
 def test_delete_returning_pre_image(self):
  self.assertEqual(self.js('delete',"WHERE title = 'beta' RETURNING record, title, n"),[['x/b','beta',None]]);self.assertEqual(self.sel('record'),[['x/a']])
 def test_add_members_and_link_returning(self):
  self.sql('alter','TABLE ALTER FIELD n SET CARDINALITY [0-3]')
  self.assertEqual(self.js('insert',"INTO . ADD TO n VALUES (5) WHERE record = 'x/a' RETURNING record, COUNT(n)"),[['x/a',2]])
 def test_invalid_returning_refuses_before_commit(self):
  before=(self.t/'x/a/title').read_bytes();self.sql('update',"SET title='never' ALL RECORDS RETURNING nosuch",status=2);self.assertEqual((self.t/'x/a/title').read_bytes(),before)
  self.sql('insert',"RECORD 'x/z' (title) VALUES ('z') RETURNING",status=2);self.assertFalse((self.t/'x/z').exists())
 def test_no_match_returns_empty_array(self):
  self.assertEqual(self.js('update',"SET title='q' WHERE title = 'none' RETURNING record"),[])
 def test_returning_inside_transaction_reads_staged_post_image(self):
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.assertEqual(self.js('update',"SET title='staged' WHERE record = 'x/a' RETURNING title",ctx=c),[['staged']])
  self.assertEqual(sorted(self.sel('title')),[['alpha'],['beta']]);self.sql('rollback','',ctx=c);self.assertEqual(sorted(self.sel('title')),[['alpha'],['beta']])
class Dependencies(Base):
 def view(self,name='v',linked=False,src=None):
  v=self.base/name;self.sql('create',f"VIEW {q(v)} {'LINKED ' if linked else ''}AS SELECT title FROM {q(src or self.t)}");return v
 def deps(self,path=None):return [json.loads(l) for l in self.sql('show',f'DEPENDENTS OF {q(path or self.t)}').stdout.decode().splitlines()]
 def test_saved_linked_nested_and_branch_dependents_registered(self):
  v=self.view();w=self.view('w',linked=True);n=self.view('n',src=v)
  mv=self.base/'mv';self.sql('create',f"VIEW {q(mv)} LINKED BRANCHES (one AS SELECT title FROM {q(self.t)})")
  self.assertEqual(sorted(d['path'] for d in self.deps()),sorted(map(str,[v,w,mv/'one'])));self.assertEqual([d['path'] for d in self.deps(v)],[str(n)])
  self.assertTrue(all(d['kind']=='view' for d in self.deps()))
 def test_restrict_is_default_and_dependents_must_go_first(self):
  v=self.view();n=self.view('n',src=v)
  for s in ('TABLE','TABLE RESTRICT','TABLE INCLUDING DATA'):self.sql('drop',s,status=4)
  self.sql('drop',f'VIEW {q(v)}',status=4);self.sql('drop',f'VIEW {q(n)}');self.sql('drop',f'VIEW {q(v)}');self.assertEqual(self.deps(),[]);self.sql('drop','TABLE');self.assertFalse((self.t/'.table').exists());self.assertTrue((self.t/'x/a/title').exists())
 def test_stale_entries_pruned_after_crash_style_removal(self):
  v=self.view();(v/'.view').unlink();self.assertEqual(self.deps(),[]);self.sql('drop','TABLE VALIDATE ONLY');self.assertEqual(list((self.t/'.sql'/'deps').iterdir()),[])
 def test_identity_change_is_stale(self):
  v=self.view();os.rename(v,self.base/'moved');v.mkdir();self.assertEqual(self.deps(),[])
 def test_cascade_deliberately_refused(self):
  self.view();self.sql('drop','TABLE CASCADE',status=7);self.assertTrue((self.t/'.table').exists())
 def test_alter_restricts_referenced_fields_only(self):
  self.view();self.sql('alter','TABLE RENAME FIELD title TO head',status=4);self.sql('alter','TABLE DROP FIELD title INCLUDING DATA',status=4);self.sql('alter','TABLE ALTER FIELD title SET TYPE OCTETS',status=4)
  self.sql('alter','TABLE RENAME FIELD n TO num');self.assertEqual(sorted(map(json.dumps,self.sel('num'))),['[1]','[null]'])
class DropIncludingData(Base):
 def test_table_purge_removes_only_managed_entries(self):
  self.sql('drop','TABLE INCLUDING DATA VALIDATE ONLY');self.assertTrue((self.t/'x/a/title').exists())
  self.sql('drop','TABLE INCLUDING DATA');left=sorted(p.name for p in self.t.iterdir());self.assertNotIn('x',left);self.assertNotIn('.table',left);self.assertNotIn('.sql',left)
  self.sql('create','TABLE (r DIRECTORY RECORD (k INT64))')
 def test_unmanaged_entries_refuse_whole_drop(self):
  self.sql('alter','TABLE SET UNMATCHED IGNORE');(self.t/'x/a/notes.txt').write_text('mine')
  self.sql('drop','TABLE INCLUDING DATA',status=4);self.assertEqual((self.t/'x/a/notes.txt').read_text(),'mine');self.assertTrue((self.t/'x/a/title').exists());self.assertTrue((self.t/'.table').exists())
 def test_empty_groups_and_shared_anchors_removed(self):
  self.sql('delete',"WHERE record = 'x/b'");(self.t/'y').mkdir();self.sql('drop','TABLE INCLUDING DATA');self.assertFalse((self.t/'y').exists());self.assertFalse((self.t/'x').exists())
 def test_pending_journal_refuses(self):
  (self.t/'.sql-txn.0123456789abcdef0123456789abcdef').mkdir();self.sql('drop','TABLE INCLUDING DATA',status=4);self.assertTrue((self.t/'x/a/title').exists())
 def test_linked_view_purge_keeps_source_and_refuses_foreign_files(self):
  v=self.base/'lv';self.sql('create',f"VIEW {q(v)} LINKED AS SELECT title FROM {q(self.t)}");(v/'mine').write_text('x')
  self.sql('drop',f'VIEW {q(v)} INCLUDING DATA',status=4);(v/'mine').unlink()
  self.sql('drop',f'VIEW {q(v)} INCLUDING DATA');self.assertEqual(list(v.iterdir()),[]);self.assertEqual((self.t/'x/a/title').read_text(),'alpha');self.sql('drop','TABLE')
 def test_multiview_purge_removes_branches(self):
  mv=self.base/'mv';self.sql('create',f"VIEW {q(mv)} LINKED BRANCHES (one AS SELECT title FROM {q(self.t)} ; two AS SELECT n FROM {q(self.t)})")
  self.sql('drop','TABLE',status=4);self.sql('drop',f'VIEW {q(mv)} INCLUDING DATA');self.assertEqual(list(mv.iterdir()),[]);self.sql('drop','TABLE INCLUDING DATA')
class Alter(Base):
 def ddl(self):return self.sql('describe','TABLE').stdout.decode()
 def test_add_field_backfills_default_or_refuses(self):
  self.sql('alter','TABLE ADD FIELD score UINT64',status=4);self.assertNotIn('score',self.ddl())
  self.sql('alter',"TABLE ADD FIELD score UINT64 DEFAULT '0'");self.assertEqual(sorted(self.sel('record, score')),[['x/a',0],['x/b',0]]);self.assertEqual((self.t/'x/a/score').read_text(),'0')
  self.sql('alter','TABLE ADD FIELD note TEXT [0-1]');self.sql('insert',"RECORD 'x/c' (title,note) VALUES ('c','hello')");self.assertEqual(self.sel("note WHERE record = 'x/c'"),[['hello']])
  self.sql('alter','TABLE ADD FIELD nul TEXT DEFAULT NULL');self.assertEqual(self.sel("nul WHERE record = 'x/a'"),[[None]])
 def test_add_field_invalid_declaration_or_duplicate(self):
  self.sql('alter','TABLE ADD FIELD title TEXT [0-1]',status=4);self.sql('alter','TABLE ADD FIELD bad NOPE',status=2);self.sql('alter',"TABLE ADD FIELD i INT64 DEFAULT 'x'",status=4)
 def test_rename_field_moves_implicit_files_and_nulls(self):
  self.sql('update',"SET n = NULL WHERE record = 'x/a'");self.sql('alter','TABLE RENAME FIELD n TO num');self.assertTrue((self.t/'x/a/num').exists());self.assertTrue((self.t/'x/a/.sql-null.num').exists());self.assertEqual(self.sel("num WHERE record = 'x/a'"),[[None]]);self.sql('check','TABLE DEEP')
 def test_rename_capture_and_match_field_keeps_files(self):
  self.sql('alter',"TABLE ADD FIELD pic OCTETS [0-] MATCH 'p([0-9]+)' CAPTURE (pno UINT64)");self.sql('insert',"INTO . ADD TO pic VALUES (NAMED 'p7' 'raw') WHERE record = 'x/a'")
  self.sql('alter','TABLE RENAME FIELD pic TO photo');self.sql('alter','TABLE RENAME CAPTURE pno TO number');self.assertTrue((self.t/'x/a/p7').exists());self.assertEqual(self.sel("ANY(photo, number = 7) WHERE record = 'x/a'"),[[True]])
 def test_drop_field_requires_including_data(self):
  self.sql('alter','TABLE DROP FIELD n',status=4);self.sql('alter','TABLE DROP FIELD n INCLUDING DATA VALIDATE ONLY');self.assertTrue((self.t/'x/a/n').exists())
  self.sql('alter','TABLE DROP FIELD n INCLUDING DATA');self.assertFalse((self.t/'x/a/n').exists());self.assertNotIn(' n ',self.ddl());self.sql('alter','TABLE DROP FIELD r',status=2)
 def test_set_type_validates_every_value(self):
  self.sql('alter','TABLE ALTER FIELD title SET TYPE INT64',status=4);self.assertIn('title TEXT',self.ddl());self.sql('alter','TABLE ALTER FIELD n SET TYPE UINT64');self.assertIn('n UINT64',self.ddl())
  self.sql('alter','TABLE ALTER FIELD title SET TYPE JPG',status=7)
 def test_not_null_and_default_and_cardinality(self):
  self.sql('update',"SET n = NULL WHERE record = 'x/a'");self.sql('alter','TABLE ALTER FIELD n SET NOT NULL',status=4);self.sql('update',"SET n = 2 WHERE record = 'x/a'");self.sql('alter','TABLE ALTER FIELD n SET NOT NULL');self.sql('alter','TABLE ALTER FIELD n DROP NOT NULL')
  self.sql('alter',"TABLE ALTER FIELD n SET DEFAULT '9'");self.sql('insert',"RECORD 'x/d' (title) VALUES ('d')");self.assertEqual(self.sel("n WHERE record = 'x/d'"),[[9]]);self.sql('alter','TABLE ALTER FIELD n DROP DEFAULT');self.assertNotIn('DEFAULT',self.ddl())
  self.sql('alter','TABLE ALTER FIELD n SET CARDINALITY [0-3]');self.assertTrue((self.t/'x/a/n.1').exists());self.sql('insert',"INTO . ADD TO n VALUES (4) WHERE record = 'x/a'")
  self.sql('alter','TABLE ALTER FIELD n SET CARDINALITY [0-1]',status=4);self.sql('delete',"MEMBERS n WHERE record = 'x/a' AND CONTENT(n) = 4");self.sql('alter','TABLE ALTER FIELD n SET CARDINALITY [0-1]');self.assertTrue((self.t/'x/a/n').exists());self.sql('check','TABLE DEEP')
  self.sql('alter','TABLE ALTER FIELD title SET CARDINALITY [2-2]',status=4)
 def test_policy_changes(self):
  s=self.t/'x/a/stray.txt';s.write_text('s');self.sql('select','title',status=4);self.sql('alter','TABLE ALTER FIELD n SET NOT NULL',status=4)
  s.unlink();self.sql('alter','TABLE SET UNMATCHED IGNORE');s.write_text('s');self.assertEqual(len(self.sel('title')),2);self.sql('alter','TABLE SET LINKS INTERNAL');self.assertIn('LINKS INTERNAL',self.ddl())
 def test_generation_increments_and_validate_only_changes_nothing(self):
  before=(self.t/'.table').read_bytes();self.sql('alter',"TABLE ADD FIELD k INT64 DEFAULT '1' VALIDATE ONLY");self.assertEqual((self.t/'.table').read_bytes(),before);self.assertFalse((self.t/'x/a/k').exists())
  self.sql('alter','TABLE ADD FIELD k INT64 [0-1]');self.assertNotEqual((self.t/'.table').read_bytes()[24:32],before[24:32])
 def test_syntax_errors(self):
  for s in ('TABLE','TABLE ADD','TABLE ALTER FIELD n','TABLE ALTER FIELD n SET','TABLE SET NOTHING','TABLE ALTER FIELD zz SET NOT NULL'):self.sql('alter',s,status=2)
class TransactionalDDL(Base):
 def test_create_table_and_view_commit_publishes(self):
  c=self.ctx();u=self.base/'u';v=self.base/'v';self.sql('begin','READ WRITE',ctx=c)
  self.sql('create',f"TABLE {q(u)} (r DIRECTORY RECORD (k INT64))",ctx=c);self.sql('insert',f"INTO {q(u)} RECORD 'z' (k) VALUES (4)",ctx=c);self.sql('create',f"VIEW {q(v)} AS SELECT title FROM {q(self.t)}",ctx=c)
  self.assertEqual(self.sel(f'k FROM {q(u)}',ctx=c),[[4]]);self.assertEqual(sorted(self.sel(f'* FROM {q(v)}',ctx=c)),[['alpha'],['beta']])
  self.assertFalse((u/'.table').exists());self.assertFalse((v/'.view').exists());self.sql('select',f'k FROM {q(u)}',status=3)
  self.sql('commit','',ctx=c);self.assertEqual(self.sel(f'k FROM {q(u)}'),[[4]]);self.assertEqual(len(self.sel(f'* FROM {q(v)}')),2);self.sql('drop','TABLE',status=4)
 def test_rollback_discards_created_definitions(self):
  c=self.ctx();u=self.base/'u';u.mkdir();self.sql('begin','READ WRITE',ctx=c);self.sql('create',f"TABLE {q(u)} (r DIRECTORY RECORD (k INT64))",ctx=c);self.sql('rollback','',ctx=c);self.assertEqual(list(u.iterdir()),[])
 def test_concurrent_create_conflicts(self):
  c=self.ctx();u=self.base/'u';u.mkdir();self.sql('begin','READ WRITE',ctx=c);self.sql('create',f"TABLE {q(u)} (r DIRECTORY RECORD (k INT64))",ctx=c)
  self.sql('create','TABLE (r DIRECTORY RECORD (other TEXT))',cwd=u);self.sql('commit','',ctx=c,status=4);self.assertIn('other',self.sql('describe','TABLE',cwd=u).stdout.decode())
 def test_transactional_alter_and_drop(self):
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.sql('alter',f"TABLE {q(self.t)} ADD FIELD k INT64 DEFAULT '3'",ctx=c);self.assertEqual(sorted(self.sel(f'title, k FROM {q(self.t)}',ctx=c)),[['alpha',3],['beta',3]])
  self.assertNotIn(' k ',self.sql('describe','TABLE').stdout.decode());self.sql('commit','',ctx=c);self.assertEqual(sorted(self.sel('k')),[[3],[3]])
  self.sql('begin','READ WRITE',ctx=c);self.sql('drop',f'TABLE {q(self.t)} INCLUDING DATA',ctx=c);self.sql('select',f'title FROM {q(self.t)}',ctx=c,status=3);self.assertEqual(len(self.sel('title')),2);self.sql('commit','',ctx=c);self.assertFalse((self.t/'.table').exists());self.assertFalse((self.t/'x').exists())
 def test_transactional_drop_respects_live_dependents_and_rollback(self):
  v=self.base/'v';self.sql('create',f"VIEW {q(v)} AS SELECT title FROM {q(self.t)}");c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.sql('drop',f'TABLE {q(self.t)}',ctx=c,status=4)
  self.sql('drop',f'VIEW {q(v)}',ctx=c);self.assertTrue((v/'.view').exists());self.sql('rollback','',ctx=c);self.assertTrue((v/'.view').exists())
  self.sql('begin','READ WRITE',ctx=c);self.sql('drop',f'VIEW {q(v)}',ctx=c);self.sql('commit','',ctx=c);self.assertFalse((v/'.view').exists());self.sql('drop','TABLE')
 def test_linked_view_read_in_transaction_sees_staged_source_without_publishing(self):
  v=self.base/'lv';self.sql('create',f"VIEW {q(v)} LINKED AS SELECT title FROM {q(self.t)}");before=os.readlink(v/'records');c=self.ctx();self.sql('begin','READ WRITE',ctx=c)
  self.sql('update',f"{q(self.t)} SET title='staged' WHERE record = 'x/a'",ctx=c);self.assertIn(['staged'],self.sel(f'* FROM {q(v)}',ctx=c));self.assertEqual(os.readlink(v/'records'),before)
  self.sql('create',f"VIEW {q(self.base/'lv2')} LINKED AS SELECT title FROM {q(self.t)}",ctx=c,status=7);self.sql('commit','',ctx=c);self.assertIn(['staged'],self.sel(f'* FROM {q(v)}'))
 def test_multiview_admin_in_transaction_refused(self):
  mv=self.base/'mv';self.sql('create',f"VIEW {q(mv)} LINKED BRANCHES (one AS SELECT title FROM {q(self.t)})");c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.sql('drop',f'VIEW {q(mv)}',ctx=c,status=7);self.sql('rollback','',ctx=c)
if __name__=='__main__':unittest.main()
