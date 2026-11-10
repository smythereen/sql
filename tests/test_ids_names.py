#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Adopted immutable record IDs, record_id, generated record/group names and
multi-value FORMAT.  /tmp scratch fixtures only."""
import json,os,pathlib,subprocess,tempfile,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1];SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def q(s):return "'"+str(s).replace("'","''")+"'"
GEN="TABLE (g DIRECTORY FORMAT 'g%03u' MATCH 'g[0-9]+' (r DIRECTORY RECORD [0-2] FORMAT 'r%u' MATCH 'r[0-9]+' (photo JPG [0-] FORMAT 'IMG_%03u_%u.jpg' MATCH 'IMG_[0-9]+_[0-9]+[.]jpg', title TEXT [0-1])))"
class Base(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-ids-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name);self.t=self.base/'t';self.t.mkdir()
  self.env={k:v for k,v in os.environ.items() if k not in('SQL_CONTEXT','DATABASE_DIR')};self.env['DATABASE_DIR']=str(self.base)
  self.jpg=self.base/'p.jpg';self.jpg.write_bytes(b'\xff\xd8x\xff\xd9')
 def sql(self,verb,text='',status=0,cwd=None,ctx=None):
  env=dict(self.env)
  if ctx:env['SQL_CONTEXT']=ctx
  p=subprocess.run([str(SQL),verb,text],cwd=cwd or self.t,env=env,capture_output=True,timeout=20);self.assertEqual(p.returncode,status,(verb,text,p.returncode,p.stdout,p.stderr))
  return p
 def js(self,verb,text,**k):return json.loads(self.sql(verb,text,**k).stdout)
 def ctx(self):return self.sql('context',f'CREATE ON {q(self.base)} OWNER {os.getpid()}').stdout.decode().strip()
 def gen(self,clause='',values="('x')",cols='(title)',**k):return self.js('insert',f"RECORD GENERATED {clause} {cols} VALUES {values} RETURNING record",**k)
class Generated(Base):
 def setUp(self):super().setUp();self.sql('create',GEN)
 def test_auto_numbering_and_group_rollover(self):
  self.assertEqual([self.gen()[0][0] for _ in range(5)],['g001/r1','g001/r2','g002/r1','g002/r2','g003/r1'])
 def test_using_values_fill_conversions_in_order(self):
  self.assertEqual(self.gen('USING (7, 9)'),[['g007/r9']]);self.assertEqual(self.gen('USING (7)'),[['g007/r10']])
 def test_under_names_group_and_record_continues_after_highest(self):
  (self.t/'g004').mkdir();self.assertEqual(self.gen("UNDER 'g004'"),[['g004/r1']]);self.sql('delete',"WHERE record='g004/r1'")
  self.assertEqual(self.gen("UNDER 'g004' USING (5)"),[['g004/r5']]);self.assertEqual(self.gen("UNDER 'g004'"),[['g004/r6']])
 def test_full_group_with_explicit_value_refused(self):
  self.gen();self.gen();self.sql('insert',"RECORD GENERATED USING (1) (title) VALUES ('z')",status=4);self.assertFalse((self.t/'g001'/'r3').exists())
 def test_wrong_value_counts_refused(self):
  self.sql('insert',"RECORD GENERATED USING (1, 2, 3) (title) VALUES ('z')",status=4)
  self.sql('insert',"RECORD GENERATED USING (x) (title) VALUES ('z')",status=2)
  self.sql('insert',"RECORD GENERATED UNDER 'nope' (title) VALUES ('z')",status=4)
  self.assertEqual([p.name for p in self.t.iterdir() if not p.name.startswith('.')],[])
 def test_member_multi_value_format_uses_path_values_then_ordinal(self):
  rows=self.js('insert',f"RECORD GENERATED USING (3, 4) (photo, photo) VALUES (FILE({q(self.jpg)}), FILE({q(self.jpg)})) RETURNING PATH(photo)")
  self.assertEqual([pathlib.Path(r[0]).name for r in rows],['IMG_004_1.jpg','IMG_004_2.jpg'])
  self.sql('insert',f"INTO . ADD TO photo VALUES (FILE({q(self.jpg)})) WHERE record = 'g003/r4'");self.assertTrue((self.t/'g003'/'r4'/'IMG_004_3.jpg').exists())
 def test_generated_inside_transaction_rolls_back(self):
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.assertEqual(self.gen(ctx=c),[['g001/r1']]);self.sql('rollback','',ctx=c);self.assertFalse((self.t/'g001').exists())
  self.sql('begin','READ WRITE',ctx=c);self.gen(ctx=c);self.sql('commit','',ctx=c);self.assertTrue((self.t/'g001'/'r1'/'.sql-id').exists())
 def test_formatless_level_refused_and_sibling_groups_skipped(self):
  b=self.base/'b';b.mkdir();self.sql('create',"TABLE (r DIRECTORY RECORD (title TEXT))",cwd=b);self.sql('insert',"RECORD GENERATED (title) VALUES ('q')",cwd=b,status=4)
  self.assertEqual(self.gen("UNDER 'g002'"),[['g002/r1']])
 def test_generated_name_must_satisfy_match(self):
  a=self.base/'a';a.mkdir();self.sql('create',"TABLE (r DIRECTORY RECORD FORMAT 'n%u' MATCH 'n[0-5]' (title TEXT))",cwd=a)
  self.sql('insert',"RECORD GENERATED USING (5) (title) VALUES ('q')",cwd=a);self.sql('insert',"RECORD GENERATED (title) VALUES ('q')",cwd=a,status=4)
 def test_format_padding_semantics(self):
  a=self.base/'a';a.mkdir();self.sql('create',"TABLE (r DIRECTORY RECORD FORMAT 'a%05u-%.3u-%%' (title TEXT))",cwd=a)
  self.assertEqual(self.js('insert',"RECORD GENERATED USING (42, 7) (title) VALUES ('q') RETURNING record",cwd=a),[['a00042-007-%']])
class Ids(Base):
 def setUp(self):
  super().setUp()
  for n in ('x1','x2'):(self.t/n).mkdir();(self.t/n/'title').write_text(n)
  self.before=sorted(str(p.relative_to(self.t)) for p in self.t.rglob('*'))
  self.sql('define','TABLE (r DIRECTORY RECORD (title TEXT))')
 def ids(self,**k):return dict(self.js('select','record, record_id',**k))
 def test_define_adopts_without_touching_records(self):
  ids=self.ids();self.assertEqual(sorted(ids),['x1','x2']);self.assertTrue(all(len(v)==32 for v in ids.values()))
  self.assertEqual(sorted(str(p.relative_to(self.t)) for p in self.t.rglob('*') if not str(p.relative_to(self.t)).startswith('.')),self.before)
 def test_ids_survive_rename_and_are_stable(self):
  ids=self.ids();self.sql('alter','TABLE RENAME RECORD x1 TO y1');os.rename(self.t/'x2',self.t/'z2')
  self.assertEqual(self.ids(),{'y1':ids['x1'],'z2':ids['x2']});self.assertEqual(self.ids(),{'y1':ids['x1'],'z2':ids['x2']})
 def test_inserted_record_uses_sql_id(self):
  row=self.js('insert',"RECORD n (title) VALUES ('n') RETURNING record_id");self.assertEqual(row[0][0],(self.t/'n'/'.sql-id').read_text())
 def test_adopt_ids_idempotent_and_prunes(self):
  self.assertEqual(self.js('alter','TABLE ADOPT IDS'),{'adopted':0,'existing':2,'pruned':0})
  (self.t/'x3').mkdir();(self.t/'x3'/'title').write_text('3');self.assertIsNone(self.ids()['x3'])
  self.assertEqual(self.js('alter','TABLE ADOPT IDS'),{'adopted':1,'existing':2,'pruned':0});self.assertEqual(len(self.ids()['x3']),32)
  import shutil;shutil.rmtree(self.t/'x2');self.assertEqual(self.js('alter','TABLE ADOPT IDS'),{'adopted':0,'existing':2,'pruned':1})
 def test_recycled_inode_not_mistaken(self):
  ids=self.ids();e=next(p for p in (self.t/'.sql'/'ids').iterdir() if p.read_text().split('\n')[2]=='x1')
  lines=e.read_text().split('\n')
  if lines[1]=='0':self.skipTest('filesystem has no birth time')
  lines[1]='1.000000001';e.write_text('\n'.join(lines));self.assertIsNone(self.ids()['x1'])
  self.sql('alter','TABLE ADOPT IDS');self.assertNotEqual(self.ids()['x1'],ids['x1'])
 def test_where_and_transaction_reads(self):
  ids=self.ids();self.assertEqual(self.js('select',f"record WHERE record_id = {q(ids['x2'])}"),[['x2']])
  c=self.ctx();self.sql('begin','READ WRITE',ctx=c);self.assertEqual(self.ids(ctx=c),ids);self.sql('alter','TABLE ADOPT IDS',ctx=c,status=7);self.sql('rollback','',ctx=c)
 def test_registry_is_private_and_excluded(self):
  d=self.t/'.sql'/'ids';self.assertEqual(d.stat().st_mode&0o777,0o700);self.sql('check','TABLE ALL')
if __name__=='__main__':unittest.main()
