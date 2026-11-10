#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Cross-table shared fields and reverse references.  /tmp scratch only."""
import json,os,pathlib,subprocess,tempfile,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1];SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def q(s):return "'"+str(s).replace("'","''")+"'"
SCHEMA="TABLE (r DIRECTORY RECORD (title TEXT, n INT64 [0-1])) LINKS INTERNAL"
class X(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-xshare-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name)
  self.env={k:v for k,v in os.environ.items() if k not in('SQL_CONTEXT','DATABASE_DIR')};self.env['DATABASE_DIR']=str(self.base)
  self.s=self.base/'s';self.d=self.base/'d'
  for t in (self.s,self.d):t.mkdir();self.sql('create',SCHEMA,cwd=t)
  self.sql('insert',"RECORD a (title,n) VALUES ('src',1)",cwd=self.s)
  for r in 'bc':self.sql('insert',f"RECORD {r} (title) VALUES ('dst-{r}')",cwd=self.d)
 def sql(self,verb,text='',status=0,cwd=None,ctx=None):
  env=dict(self.env)
  if ctx:env['SQL_CONTEXT']=ctx
  p=subprocess.run([str(SQL),verb,text],cwd=cwd or self.d,env=env,capture_output=True,timeout=20);self.assertEqual(p.returncode,status,(verb,text,p.returncode,p.stdout,p.stderr))
  return p
 def titles(self,t):return dict(json.loads(self.sql('select','record, title',cwd=t).stdout))
 def link(self,scope='ALL RECORDS',**k):return self.sql('link',f"FIELD title TO 'a/title' FROM SOURCE {q(self.s)} {scope}",**k)
 def refs(self):return [json.loads(l) for l in self.sql('show',f'REFERENCES OF {q(self.s)}').stdout.decode().splitlines()]
 def ctx(self):return self.sql('context',f'CREATE ON {q(self.base)} OWNER {os.getpid()}').stdout.decode().strip()
 def test_link_promotes_source_and_creates_absolute_symlinks(self):
  self.link();anchor=os.readlink(self.s/'a'/'title');self.assertTrue(anchor.startswith('../.sql/shared/'))
  for r in 'bc':self.assertEqual(os.readlink(self.d/r/'title'),str(self.s/anchor[3:]))
  self.assertEqual(self.titles(self.d),{'b':'src','c':'src'})
 def test_reverse_references_and_dependents(self):
  self.link("WHERE record = 'b'");r=self.refs()
  self.assertEqual(sorted((x['table'],x['record'],x['field']) for x in r),[(str(self.d),'b','title'),(str(self.s),'a','title')])
  deps=[json.loads(l) for l in self.sql('show',f'DEPENDENTS OF {q(self.s)}').stdout.decode().splitlines()];self.assertEqual(deps,[{'kind':'link','path':str(self.d)}])
 def test_update_through_consumer_writes_owner_anchor(self):
  self.link();self.sql('update',"SET title='through consumer' WHERE record='b'")
  self.assertEqual(self.titles(self.s),{'a':'through consumer'});self.assertEqual(self.titles(self.d),{'b':'through consumer','c':'through consumer'})
 def test_update_through_owner_visible_in_consumer(self):
  self.link();self.sql('update',"SET title='owner' ALL RECORDS",cwd=self.s);self.assertEqual(self.titles(self.d)['c'],'owner')
 def test_source_drop_restricted_while_referenced(self):
  self.link();self.sql('drop','TABLE',cwd=self.s,status=4);self.sql('drop','TABLE INCLUDING DATA',cwd=self.s,status=4);self.assertTrue((self.s/'.table').exists())
 def test_unlink_materializes_private_copy_and_prunes(self):
  self.link();self.sql('unlink','FIELD title ALL RECORDS');self.assertFalse((self.d/'b'/'title').is_symlink());self.assertEqual(self.titles(self.d),{'b':'src','c':'src'})
  self.assertEqual([x['table'] for x in self.refs()],[str(self.s)])
  self.sql('update',"SET title='private' WHERE record='b'");self.assertEqual(self.titles(self.s),{'a':'src'})
 def test_check_links_verifies_anchor_and_registration(self):
  self.link();self.sql('check','TABLE LINKS')
  for e in (self.s/'.sql'/'deps').iterdir():e.unlink()
  self.sql('check','TABLE LINKS',status=4)
 def test_broken_cross_anchor_refused(self):
  self.link();anchor=self.s/'a'/os.readlink(self.s/'a'/'title');os.unlink(anchor.resolve())
  self.sql('check','TABLE LINKS',status=4);self.sql('select','title',status=4)
 def test_type_mismatch_with_consumer_refused_atomically(self):
  # d.n is INT64, the owner's a/title holds TEXT 'src': link refused, nothing changed.
  self.sql('insert',"RECORD m (title,n) VALUES ('m',7)")
  self.sql('link',f"FIELD n TO 'a/title' FROM SOURCE {q(self.s)} WHERE record='m'",status=4)
  self.assertFalse((self.d/'m'/'n').is_symlink());self.assertEqual((self.d/'m'/'n').read_text(),'7')
  # Source promotion/registration may already be durable (intention); no consumer reference exists.
  self.assertNotIn(str(self.d),[x['table'] for x in self.refs()]);self.sql('drop','TABLE',cwd=self.s)
 def test_consumer_update_validated_by_other_consumers(self):
  e=self.base/'e';e.mkdir();self.sql('create',"TABLE (r DIRECTORY RECORD (num INT64)) LINKS INTERNAL",cwd=e);self.sql('insert',"RECORD z (num) VALUES (5)",cwd=e)
  self.sql('update',"SET title='12' ALL RECORDS",cwd=self.s);self.link();self.sql('link',f"FIELD num TO 'a/title' FROM SOURCE {q(self.s)} ALL RECORDS",cwd=e)
  self.assertEqual(json.loads(self.sql('select','num',cwd=e).stdout),[[12]])
  self.sql('update',"SET title='not a number' WHERE record='b'",status=4);self.assertEqual(self.titles(self.s),{'a':'12'})
  self.sql('update',"SET title='nope' ALL RECORDS",cwd=self.s,status=4);self.assertEqual(self.titles(self.d)['b'],'12')
  self.sql('update',"SET title='34' WHERE record='c'");self.assertEqual(json.loads(self.sql('select','num',cwd=e).stdout),[[34]])
 def test_link_to_null_source_refused(self):
  self.sql('link',f"FIELD n TO 'a/missing' FROM SOURCE {q(self.s)} ALL RECORDS",status=4)
 def test_transaction_link_and_update_commit_atomically(self):
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.link(ctx=c);self.sql('update',"SET title='tx' WHERE record='c'",ctx=c)
  self.assertFalse((self.d/'b'/'title').is_symlink());self.assertEqual(self.titles(self.s),{'a':'src'})
  self.sql('commit','',ctx=c);self.assertEqual(self.titles(self.s),{'a':'tx'});self.assertEqual(self.titles(self.d),{'b':'tx','c':'tx'})
 def test_transaction_rollback_leaves_no_links(self):
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.link(ctx=c);self.sql('rollback','',ctx=c)
  self.assertFalse((self.d/'b'/'title').is_symlink());self.assertFalse((self.s/'a'/'title').is_symlink());self.assertEqual(self.refs(),[])
 def test_stale_registration_after_crash_is_pruned(self):
  # Registration precedes symlink creation; a consumer that never linked is pruned lazily.
  self.link("WHERE record = 'b'");self.sql('unlink',"FIELD title WHERE record='b'");self.sql('drop','TABLE',cwd=self.s)
 def test_chained_link_resolves_to_owner(self):
  e=self.base/'e';e.mkdir();self.sql('create',SCHEMA,cwd=e);self.sql('insert',"RECORD z (title) VALUES ('zz')",cwd=e)
  self.link("WHERE record='b'");self.sql('link',f"FIELD title TO 'b/title' FROM SOURCE {q(self.d)} ALL RECORDS",cwd=e)
  self.assertEqual(os.readlink(e/'z'/'title'),os.readlink(self.d/'b'/'title'));self.assertEqual(sorted(x['table'] for x in self.refs()),sorted(map(str,[self.s,self.d,e])))
 def test_link_back_into_owner_refused(self):
  self.link("WHERE record='b'");self.sql('link',f"FIELD title TO 'b/title' FROM SOURCE {q(self.d)} ALL RECORDS",cwd=self.s,status=4)
 def test_fs_target_metadata_for_cross_anchor(self):
  self.link("WHERE record='b'");rows=json.loads(self.sql('select',"record WHERE ANY(title, fs.target.size_bytes = 3)").stdout);self.assertEqual(rows,[['b']])
if __name__=='__main__':unittest.main()
