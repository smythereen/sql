#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Only explicit context CREATE root precedence; private scratch directories."""
import os,pathlib,subprocess,tempfile,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1];SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')));CLIENT=UNIT/'tests/context-root-client'
def q(s):return "'"+str(s).replace("'","''")+"'"
class ContextRootDefault(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-context-root-default-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name);self.work=self.base/'work';self.work.mkdir();self.chosen=self.base/'chosen';self.chosen.mkdir();self.other=self.base/'other';self.other.mkdir()
 def run_create(self,text='CREATE',database=None,status=0,api=False):
  env={k:v for k,v in os.environ.items() if k not in ('SQL_CONTEXT','DATABASE_DIR')}
  if database is not None:env['DATABASE_DIR']=str(database)
  args=[str(CLIENT),str(self.work),text] if api else [str(SQL),'context',text]
  p=subprocess.run(args,cwd=self.base if api else self.work,env=env,capture_output=True,timeout=5);self.assertEqual(p.returncode,status,(args,p.returncode,p.stdout,p.stderr))
  if status:self.assertEqual(p.stdout,b'')
  return p
 def expect_root(self,p,root):
  expected=root/'.context'/str(os.getpid());self.assertEqual(p.stdout.decode().strip(),str(expected));self.assertTrue((expected/'.state').is_file());self.assertFalse((self.work/'.context').exists() if root!=self.work else False)
 def test_explicit_absolute_wins_over_different_env(self):
  self.expect_root(self.run_create('CREATE ON '+q(self.chosen),self.other),self.chosen);self.assertFalse((self.other/'.context').exists())
 def test_explicit_absolute_wins_over_invalid_env(self):
  self.expect_root(self.run_create('CREATE ON '+q(self.chosen),self.base/'does-not-exist'),self.chosen)
 def test_omitted_on_uses_database_dir(self):self.expect_root(self.run_create(database=self.chosen),self.chosen)
 def test_explicit_dot_wins_over_environment(self):
  self.expect_root(self.run_create("CREATE ON '.'",self.other),self.work);self.assertFalse((self.other/'.context').exists())
 def test_absent_environment_errors_without_side_effects(self):
  p=self.run_create(status=4);self.assertIn(b'DATABASE_DIR',p.stderr);self.assertEqual(list(self.work.iterdir()),[])
 def test_empty_environment_errors_without_side_effects(self):
  self.run_create(database='',status=4);self.assertEqual(list(self.work.iterdir()),[])
 def test_invalid_env_or_explicit_root_does_not_fallback(self):
  missing=self.base/'missing';self.run_create(database=missing,status=3);self.run_create('CREATE ON '+q(missing),self.chosen,status=3);self.run_create("CREATE ON ''",self.chosen,status=2);self.assertFalse(missing.exists());self.assertEqual(list(self.work.iterdir()),[]);self.assertFalse((self.chosen/'.context').exists())
 def test_spaces_and_shell_syntax_are_literal(self):
  literal=self.base/'space $(touch INJECTED) $HOME ~';literal.mkdir();self.expect_root(self.run_create(database=literal),literal);self.assertFalse((self.work/'INJECTED').exists());self.assertFalse((self.base/'INJECTED').exists())
 def test_relative_environment_uses_invocation_cwd(self):
  relative=self.work/'relative root';relative.mkdir();self.expect_root(self.run_create(database='relative root'),relative)
 def test_owner_clause_still_works_with_environment_root(self):
  self.expect_root(self.run_create(f'CREATE OWNER {os.getpid()}',self.chosen),self.chosen)
 def test_database_dir_does_not_redirect_tables_or_auto_contexts(self):
  env={k:v for k,v in os.environ.items() if k!='SQL_CONTEXT'};env['DATABASE_DIR']=str(self.base/'invalid-default')
  def run(cwd,verb,text):
   p=subprocess.run([str(SQL),verb,text],cwd=cwd,env=env,capture_output=True,timeout=5);self.assertEqual(p.returncode,0,(p.stdout,p.stderr));return p
  for directory,value in [(self.work,'here'),(self.other,'elsewhere')]:
   run(directory,'create','TABLE (r DIRECTORY RECORD (title TEXT))');run(directory,'insert',f"RECORD a (title) VALUES ('{value}')")
  env['DATABASE_DIR']=str(self.other);self.assertEqual(run(self.work,'select','title').stdout,b'[["here"]]\n');self.assertTrue((self.work/'.context'/str(os.getpid())/'.state').is_file())
 def test_direct_api_uses_same_precedence_and_missing_env_rule(self):
  self.run_create(status=4,api=True);self.assertEqual(list(self.work.iterdir()),[])
  self.expect_root(self.run_create('CREATE ON '+q(self.chosen),self.base/'invalid',api=True),self.chosen)
  self.expect_root(self.run_create(database=self.other,api=True),self.other)
if __name__=='__main__':unittest.main(verbosity=2)
