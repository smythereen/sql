#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Local engine integration tests. Python is only the test runner, not the engine."""
import ctypes,hashlib,json,os,pathlib,shutil,stat,subprocess,tempfile,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1]
SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def quoted(s):return "'"+str(s).replace("'","''")+"'"
class SQLTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-unit-test-');self.base=pathlib.Path(self.tmp.name);self.table=self.base/'table';self.table.mkdir()
 def tearDown(self):self.tmp.cleanup()
 def runsql(self,cmd,s='',ok=0,cwd=None,env=None):
  p=subprocess.run([str(SQL),cmd,s],cwd=cwd or self.table,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
  self.assertEqual(p.returncode,ok,(cmd,s,p.returncode,p.stdout,p.stderr))
  if ok not in (0,86):self.assertEqual(p.stdout,b'',('partial stdout on failure',p.stdout))
  return p
 def create(self,s="(asset DIRECTORY RECORD (title TEXT NOT NULL, age INT64, blob OCTETS [0-1]))",policy=''):
  self.runsql('create','TABLE '+s+policy)
 def insert(self,name,title='hello',age=12):self.runsql('insert',f"RECORD {quoted(name)} (title,age) VALUES ({quoted(title)}, {age})")
 def select(self,s):return json.loads(self.runsql('select',s).stdout)
 def test_create_select_cwd(self):
  self.create();self.insert('a');self.assertEqual(self.select('title,age'),[['hello',12]])
  self.assertEqual(self.select("title FROM . WHERE age >= 12 AND record = 'a'"),[['hello']])
  self.runsql('select','title',cwd=self.table/'a',ok=3)
 def test_numeric_boundaries(self):
  self.create();self.insert('low',age=-9223372036854775808);self.insert('high',age=9223372036854775807)
  self.assertEqual(self.select('age ORDER BY age DESC LIMIT 1 OFFSET 0'),[[9223372036854775807]])
  self.runsql('update',"SET age = 9223372036854775808 ALL RECORDS",ok=4)
  self.assertEqual(self.select('COUNT(blob) ORDER BY age'),[[0],[0]])
 def test_output(self):
  self.create();self.insert('a',title="a\nb ' c")
  self.runsql('select','title OUTPUT LINES',ok=4)
  self.assertEqual(self.runsql('select','title OUTPUT NUL').stdout,b"a\nb ' c\0")
  self.assertEqual(self.runsql('select','title OUTPUT RAW').stdout,b"a\nb ' c")
  self.runsql('select','title,age OUTPUT RAW',ok=4)
  self.assertEqual(self.select('title LIMIT 0'),[])
  self.runsql('select','title WHERE age = 99 REQUIRE MATCH',ok=5)
  self.assertEqual(self.select('title WHERE age = 99'),[])
 def test_binary_and_inert_script(self):
  self.create('(asset DIRECTORY RECORD (blob OCTETS, script SH))')
  data=bytes(range(256))+b'\0\xff\xfe';payload=self.base/'bytes';payload.write_bytes(data)
  self.runsql('insert',f"RECORD a (blob,script) VALUES (FILE({quoted(payload)}), '#!/bin/sh\ntouch NEVER_RUN')")
  self.assertEqual(self.runsql('select','CONTENT(blob) OUTPUT RAW').stdout,data)
  self.assertEqual(self.select('blob'),[[{'$hex':data.hex()}]])
  self.assertFalse((self.table/'NEVER_RUN').exists());self.runsql('select','blob OUTPUT NUL',ok=4)
 def test_null_empty_absent(self):
  self.create('(asset DIRECTORY RECORD (title TEXT, extra TEXT [0-1]))')
  self.runsql('insert',"RECORD a (title) VALUES (NULL)");self.runsql('insert',"RECORD b (title,extra) VALUES ('','')")
  self.assertEqual(self.select('record,title,COUNT(extra) ORDER BY record'),[['a',None,0],['b','',1]])
  self.assertEqual(self.select('record WHERE title IS NULL'),[['a']])
  self.runsql('update',"SET title = 'filled' WHERE record = 'a'")
  self.assertEqual(self.select('title ORDER BY record'),[['filled'],['']])
  self.runsql('update',"SET title = NULL WHERE record = 'b'");self.assertEqual(self.select('record WHERE title IS NOT NULL'),[['a']])
 def test_safe_mutations(self):
  self.create();self.insert('a');self.runsql('update',"SET title = 'bad'",ok=2);self.runsql('delete','',ok=2)
  self.runsql('update',"SET title = 'new' WHERE record = 'a'");self.assertEqual(self.select('title'),[['new']])
  self.runsql('delete',"WHERE record = 'a'");self.assertEqual(self.select('title'),[])
 def test_collections_sparse(self):
  self.create('(asset DIRECTORY RECORD (image JPG [1-4], video MP4 [0-]))')
  jpg=self.base/'photo';jpg.write_bytes(b'\xff\xd8photo\xff\xd9')
  self.runsql('insert',f'RECORD a (image,image,image) VALUES (FILE({quoted(jpg)}),FILE({quoted(jpg)}),FILE({quoted(jpg)}))')
  self.assertEqual(self.select('COUNT(image)'),[[3]])
  self.assertEqual(len(self.select('PATH(image) WHERE ANY(image, fs.type = \'f\')')),3)
  self.runsql('delete',"MEMBERS image WHERE fs.size_bytes > 0",ok=4)
  # Exact member matching via PATH expansion and fs metadata; sparse names are adopted unchanged.
  (self.table/'a'/'image.2.jpg').unlink();self.runsql('check','TABLE TYPES')
  self.assertEqual(len(self.select('PATH(image)')),2);self.assertTrue((self.table/'a'/'image.3.jpg').exists())
 def test_define_nested_captures_preserves(self):
  d=self.table/'my_2026'/'07';d.mkdir(parents=True);f=d/'12_35_59.jpg';data=b'\xff\xd8content\xff\xd9';f.write_bytes(data);before=hashlib.sha256(f.read_bytes()).hexdigest();mode=f.stat().st_mode
  schema=r'''(year DIRECTORY FORMAT 'my_%04.4u' MATCH '.*_([12][0-9][0-9][0-9])' CAPTURE (year UINT64) (month DIRECTORY RECORD MATCH '(0[1-9]|1[0-2])' CAPTURE (month UINT64) (image JPG [1-] MATCH '([0-9]{2})_([0-9]{2})_([0-9]{2})\.jpg' CAPTURE (hour UINT64,minute UINT64,second UINT64))))'''
  self.runsql('define','TABLE '+schema+' VALIDATE ONLY');self.assertFalse((self.table/'.table').exists())
  self.runsql('define','TABLE '+schema);self.assertEqual(self.select('year,month,hour,PATH(image) WHERE hour >= 12'),[[2026,7,12,str(f)]])
  self.assertEqual(hashlib.sha256(f.read_bytes()).hexdigest(),before);self.assertEqual(f.stat().st_mode,mode)
 def test_unmatched_and_bad_format(self):
  (self.table/'photo').write_bytes(b'x');self.runsql('create','TABLE (a DIRECTORY RECORD (title TEXT))',ok=4)
  self.runsql('define','TABLE (a DIRECTORY RECORD (title TEXT))',ok=4)
  self.runsql('define',"TABLE (a DIRECTORY RECORD MATCH 'r[0-9]+' (title TEXT)) UNMATCHED IGNORE");self.assertEqual((self.table/'photo').read_bytes(),b'x')
  other=self.base/'other';other.mkdir();self.runsql('create',"TABLE (a DIRECTORY RECORD FORMAT '%n' (title TEXT))",cwd=other,ok=4)
 def test_fs_permissions_fifo_no_open(self):
  self.create('(asset DIRECTORY RECORD (title TEXT))');self.runsql('insert',"RECORD a (title) VALUES ('x')");p=self.table/'a'/'title';p.chmod(0o750)
  self.assertEqual(self.select("COUNT(title) WHERE ANY(title, fs.mode = 0o750)"),[[1]])
  self.assertEqual(self.select("COUNT(title) WHERE ANY(title, fs.permissions IS 'o:rwx,g:r-x,w:---')"),[[1]])
  self.assertEqual(self.select("COUNT(title) WHERE ALL(title, fs.permissions HAS 'g:r..')"),[[1]])
  self.assertEqual(self.select("COUNT(title) WHERE ANY(title, fs.permissions HAS 'g:rx')"),[[1]])
  p.unlink();os.mkfifo(p);self.assertEqual(self.select("PATH(title) WHERE fs.type = 'p'"),[[str(p)]])
  self.runsql('select','CONTENT(title) OUTPUT RAW',ok=4)
 def test_link_fanout_unlink_survives_delete(self):
  self.create(policy=' LINKS INTERNAL');self.insert('a','source');self.insert('b','dest')
  self.runsql('link',"FIELD title TO 'a/title' FROM SOURCE . WHERE record = 'b'")
  self.assertTrue((self.table/'a'/'title').is_symlink());self.assertTrue((self.table/'b'/'title').is_symlink())
  self.runsql('update',"SET title = 'common' WHERE record = 'b'");self.assertEqual(self.select('title ORDER BY record'),[['common'],['common']])
  self.runsql('unlink',"FIELD title WHERE record = 'a'");self.runsql('update',"SET title = 'private' WHERE record = 'a'")
  self.assertEqual(self.select('title ORDER BY record'),[['private'],['common']]);self.runsql('delete',"WHERE record = 'a'");self.assertEqual(self.select('title'),[['common']])
  self.assertEqual(self.select("PATH(title) WHERE fs.type = 'l'"),[[str(self.table/'b'/'title')]])
 def test_external_symlink_rejected(self):
  self.create(policy=' LINKS INTERNAL');self.insert('a');p=self.table/'a'/'title';p.unlink();p.symlink_to('/etc/passwd');self.runsql('select','title',ok=4)
  self.assertEqual(self.select("PATH(title) WHERE fs.type = 'l'"),[[str(p)]])
 def test_rename_identity_drop_preserve(self):
  self.create();self.insert('a');identity=(self.table/'a'/'.sql-id').read_bytes();self.runsql('alter',"TABLE RENAME RECORD a TO b")
  self.assertEqual((self.table/'b'/'.sql-id').read_bytes(),identity);self.runsql('drop','',ok=2);self.runsql('drop','TABLE VALIDATE ONLY');self.assertTrue((self.table/'.table').exists())
  self.runsql('drop','TABLE');self.assertFalse((self.table/'.table').exists());self.assertEqual((self.table/'b'/'title').read_text(),'hello')
 def test_crash_redo(self):
  self.create();self.insert('a');env=os.environ.copy();env['SQL_TEST_CRASH']='after-decision'
  self.runsql('update',"SET title = 'durable' ALL RECORDS",ok=86,env=env);self.runsql('select','title',ok=6)
  self.runsql('recover','TABLE ALL REPORT ONLY');self.runsql('select','title',ok=6)
  self.runsql('recover','TABLE ALL APPLY');self.assertEqual(self.select('title'),[['durable']]);self.runsql('recover','TABLE ALL APPLY')
 def test_mem_dump_trace_validation(self):
  self.create();self.insert('a');tool=pathlib.Path(os.environ.get('SQL_TEST_MEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_tblmem')))
  p=subprocess.run([str(tool),str(self.table)],capture_output=True,check=True);self.assertIn(b'C.TraceLevel',p.stdout);self.assertIn(b'C.DDL',p.stdout)
  subprocess.run([str(tool),str(self.table),'C.TraceLevel','16777216'],check=True,capture_output=True)
  self.assertIn(b'SQL table',self.runsql('select','title').stderr)
  bad=subprocess.run([str(tool),str(self.table),'C.TraceLevel','4294967296'],capture_output=True);self.assertEqual(bad.returncode,2)
  # Replay must use valid logical schema, not raw offsets or pointer values.
  script=self.base/'dump.sh';script.write_bytes(p.stdout);subprocess.run(['/bin/sh',str(script)],check=True,capture_output=True)
  self.assertNotIn(b'SQL table',self.runsql('select','title').stderr)
 def test_corrupt_maps_and_syntax(self):
  self.create();p=self.table/'.table';b=bytearray(p.read_bytes());b[4:8]=(999).to_bytes(4,'little');p.write_bytes(b);self.runsql('select','title',ok=4)
  other=self.base/'other';other.mkdir();self.runsql('create',"TABLE (a DIRECTORY RECORD (x TEXT)) unexpected",cwd=other,ok=2)
  self.runsql('select',"'",ok=2);self.runsql('frobnicate','',ok=2)
 def test_unsupported_fail_closed(self):
  self.create();self.insert('a');before=(self.table/'a'/'title').read_bytes()
  for c in ('trigger','watch'):self.runsql(c,'',ok=2)
  self.runsql('create','VIEW AS SELECT title',ok=4);self.runsql('drop','TABLE INCLUDING DATA CASCADE',ok=7)
  self.assertEqual((self.table/'a'/'title').read_bytes(),before)
 def test_c_and_cpp_api(self):
  self.create();self.insert('a');libs=['-L'+str(pathlib.Path.home()/'lib'),'-lsql','-ltrigger','-lmio','-lmap','-lfar','-lnow','-lsem','-lsys','-lpthread']
  src='''#include <sql.h>\n#include <string.h>\nint main(int ac,char **av){(void)ac;SQL_Result r;SQL_Options o={0};o.cwd=av[1];int rc=SQL_Select("title",&o,&r);int bad=rc||r.size!=12||memcmp(r.data,"[[\\"hello\\"]]\\n",12);SQL_Free(&r);return bad;}'''
  for compiler,suffix in [('gcc','c'),('g++','cc')]:
   source=self.base/('client.'+suffix);source.write_text(src);exe=self.base/('client-'+suffix)
   subprocess.run([compiler,'-I'+str(pathlib.Path.home()/'cmn'),str(source),'-o',str(exe),*libs],check=True,capture_output=True)
   subprocess.run([str(exe),str(self.table)],check=True,capture_output=True)
 def test_concurrent_independent_inserts(self):
  self.create();ps=[subprocess.Popen([str(SQL),'insert',f"RECORD r{i} (title,age) VALUES ('x',{i})"],cwd=self.table,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for i in range(8)]
  for p in ps:
   out,err=p.communicate(timeout=15);self.assertEqual((p.returncode,out),(0,b''),err)
  self.assertEqual(len(self.select('record')),8)

 def test_add_members_and_explicit_updates(self):
  self.create('(asset DIRECTORY RECORD (image JPG [1-4], generator SH))')
  jpg=self.base/'jpg';jpg.write_bytes(b'\xff\xd8one\xff\xd9');jpg2=self.base/'jpg2';jpg2.write_bytes(b'\xff\xd8second\xff\xd9')
  self.runsql('insert',f"RECORD a (image,generator) VALUES (FILE({quoted(jpg)}),'echo safe')")
  self.runsql('insert',f"ADD TO image VALUES (FILE({quoted(jpg)}),FILE({quoted(jpg2)})) WHERE record = 'a'")
  self.assertEqual(self.select('COUNT(image)'),[[3]])
  self.runsql('update',f'SET image = FILE({quoted(jpg2)}) ALL RECORDS',ok=4)
  self.runsql('update',f'SET image = FILE({quoted(jpg2)}) WHERE fs.size_bytes = 7 ALL MEMBERS')
  self.assertEqual(self.select('COUNT(image) WHERE ALL(image,fs.size_bytes = 10)'),[[3]])
  self.runsql('insert',f'ADD TO image VALUES (FILE({quoted(jpg)}),FILE({quoted(jpg)})) ALL RECORDS',ok=4)
  self.assertEqual(self.select('COUNT(image)'),[[3]])
  self.runsql('delete',"MEMBERS image WHERE hour = 1",ok=2)
 def test_named_members(self):
  self.create(r"(asset DIRECTORY RECORD (image JPG [1-4] MATCH '([0-9]{2})_([0-9]{2})\.jpg' CAPTURE (hour UINT64,minute UINT64)))")
  jpg=self.base/'photo';jpg.write_bytes(b'\xff\xd8x\xff\xd9')
  self.runsql('insert',f"RECORD a (image) VALUES (NAMED '12_30.jpg' FILE({quoted(jpg)}))")
  self.runsql('insert',f"ADD TO image VALUES (NAMED '13_40.jpg' FILE({quoted(jpg)})) ALL RECORDS")
  self.assertEqual(self.select('hour,minute,PATH(image) ORDER BY hour'),[[12,30,str(self.table/'a'/'12_30.jpg')],[13,40,str(self.table/'a'/'13_40.jpg')]])
  self.runsql('insert',f"ADD TO image VALUES (NAMED '14_30.jpg' FILE({quoted(jpg)}),NAMED '14_30.jpg' FILE({quoted(jpg)})) ALL RECORDS",ok=4)
  self.assertEqual(self.select('COUNT(image)'),[[2]])
 def test_boolean_unicode_and_timestamp(self):
  self.create('(asset DIRECTORY RECORD (title TEXT, enabled BOOL))')
  self.runsql('insert',"RECORD a (title,enabled) VALUES ('café 日本語',TRUE)")
  self.assertEqual(self.select('title,enabled'),[['café 日本語',True]])
  self.assertEqual(self.select("PATH(title) WHERE fs.mtime >= TIMESTAMP '2026-01-01T00:00:00-05:00'"),[[str(self.table/'a'/'title')]])
  self.runsql('select',"PATH(title) WHERE fs.mtime > TIMESTAMP '2026-02-30T00:00:00Z'",ok=4)
  self.runsql('select',"PATH(title) WHERE fs.mtime > TIMESTAMP '2026-01-01T00:00:00'",ok=2)
 def test_typed_bindings_no_interpolation(self):
  self.create();value="x'); DELETE FROM anything; --\n' value"
  p=subprocess.run([str(SQL),'insert','--bind','v','TEXT',value,'--bind','n','INT64','23',"RECORD a (title,age) VALUES (:v,:n)"],cwd=self.table,capture_output=True)
  self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.select('title,age'),[[value,23]])
  p=subprocess.run([str(SQL),'select','--bind','v','TEXT',value,'title WHERE title = :v'],cwd=self.table,capture_output=True)
  self.assertEqual(json.loads(p.stdout),[[value]])
  self.runsql('select','title WHERE age = :missing',ok=2)
 def test_empty_tables_reject_bad_identifiers(self):
  self.create();self.runsql('select','nonsense',ok=2);self.runsql('select','title WHERE nonsense = 2',ok=2)
  self.runsql('update',"SET nonsense = 'x' ALL RECORDS",ok=2);self.runsql('delete',"WHERE nonsense = 2",ok=2)
 def test_unmanaged_delete_rejected_before_commit(self):
  self.create(policy=' UNMATCHED IGNORE');self.insert('a');extra=self.table/'a'/'keep.me';extra.write_bytes(b'untouched')
  self.runsql('delete','ALL RECORDS',ok=4);self.assertEqual(extra.read_bytes(),b'untouched');self.assertEqual(self.select('title'),[['hello']])
  self.assertEqual(list(self.table.glob('.sql-txn.*')),[])
 def test_long_map_path_and_mio_schema(self):
  parts=self.base
  for i in range(14):parts=parts/('long-directory-name-'+str(i));parts.mkdir()
  self.runsql('create','TABLE (asset DIRECTORY RECORD (title TEXT))',cwd=parts)
  self.runsql('insert',"RECORD a (title) VALUES ('x')",cwd=parts);self.assertEqual(json.loads(self.runsql('select','title',cwd=parts).stdout),[['x']])
  self.create('(asset DIRECTORY RECORD ('+', '.join('field%d TEXT [0-1]'%i for i in range(45))+'))')
  tool=pathlib.Path(os.environ.get('SQL_TEST_MEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_tblmem')));p=subprocess.run([str(tool),str(self.table)],capture_output=True,check=True)
  self.assertGreater(len(p.stdout),512);script=self.base/'dump-long.sh';script.write_bytes(p.stdout)
  subprocess.run(['/bin/sh',str(script)],check=True,capture_output=True);self.runsql('check','TABLE')
 def test_create_missing_dir_and_reusable_ddl(self):
  child=self.base/'new-table';self.runsql('create',f'TABLE {quoted(child)} (asset DIRECTORY RECORD (title TEXT))')
  self.assertTrue((child/'.table').is_file());ddl=self.runsql('describe','TABLE AS DDL',cwd=child).stdout.decode()
  other=self.base/'another';other.mkdir();self.runsql('create',ddl,cwd=other)
  result=self.runsql('show',f'TABLES IN {quoted(self.base)}');self.assertIn(b'new-table',result.stdout)
  self.runsql('show','TABLES',ok=2)
 def test_lock_timeout(self):
  import fcntl
  self.create();fd=os.open(self.table,os.O_RDONLY|os.O_DIRECTORY);fcntl.flock(fd,fcntl.LOCK_EX)
  try:
   p=subprocess.run([str(SQL),'select','--lock-timeout','20','title'],cwd=self.table,capture_output=True,timeout=2)
   self.assertEqual(p.returncode,3);self.assertEqual(p.stdout,b'')
  finally:os.close(fd)


 def test_star_collections_and_not_precedence(self):
  self.create('(asset DIRECTORY RECORD (title TEXT, age INT64, tags TEXT [0-]))')
  self.runsql('insert',"RECORD a (title,age,tags,tags) VALUES ('x',00012,'one','two')")
  self.assertEqual(self.select('*'),[['x',12,['one','two']]])
  self.assertEqual((self.table/'a'/'age').read_text(),'12')
  self.assertEqual(self.select('title WHERE NOT age = 3'),[['x']]);self.assertEqual(self.select('title WHERE NOT age = 12'),[])
  self.runsql('select','tags OUTPUT RAW',ok=4)
  self.runsql('select',"title WHERE tags = 'one'",ok=4)
 def test_ambiguous_and_duplicate_member_names(self):
  self.create("(asset DIRECTORY RECORD (image TEXT [0-4] FORMAT 'same' MATCH 'same'))")
  self.runsql('insert',"RECORD a (image,image) VALUES ('x','y')",ok=4)
  self.assertFalse((self.table/'a').exists());self.assertEqual(list(self.table.glob('.sql-txn.*')),[])
 def test_no_match_link_has_no_side_effect(self):
  self.create(policy=' LINKS INTERNAL');self.insert('a');before=(self.table/'.table').read_bytes();events=list((self.table/'.sql'/'events').iterdir())
  self.runsql('link',"FIELD title TO 'a/title' FROM SOURCE . WHERE record = 'missing'")
  self.assertFalse((self.table/'a'/'title').is_symlink());self.assertEqual((self.table/'.table').read_bytes(),before)
  self.assertEqual(list((self.table/'.sql'/'events').iterdir()),events)
 def test_check_rejects_broken_sharing(self):
  self.create(policy=' LINKS INTERNAL');self.insert('a');self.insert('b');self.runsql('link',"FIELD title TO 'a/title' FROM SOURCE . ALL RECORDS")
  next((self.table/'.sql'/'shared').iterdir()).unlink();self.runsql('check','TABLE LINKS',ok=4)
 def test_seeded_invalid_query_fuzz(self):
  import random
  self.create();self.insert('a');rng=random.Random(20261107)
  tokens=['(',')','ANY','WHERE','NULL','AND','NOT','\'','"','*',',','title','=','<=','FROM',';','0o9']
  for i in range(100):
   stmt=' '.join(rng.choice(tokens) for _ in range(rng.randrange(1,14)))
   p=subprocess.run([str(SQL),'select',stmt],cwd=self.table,capture_output=True,timeout=5)
   self.assertIn(p.returncode,[0,2,3,4,5,7],(stmt,p.returncode,p.stderr))
   if p.returncode:self.assertEqual(p.stdout,b'',stmt)


 def test_persistent_c_cpp_examples_and_archive_separation(self):
  self.create();self.insert('a')
  subprocess.run(['make','examples'],cwd=UNIT,check=True,capture_output=True)
  for name in ('c-client','cpp-client'):
   exe=UNIT/'examples'/name
   p=subprocess.run([str(exe),str(self.table),'title'],check=True,capture_output=True)
   self.assertEqual(json.loads(p.stdout),[['hello']])
   syms=subprocess.run(['nm','-g',str(exe)],check=True,capture_output=True).stdout
   self.assertIn(b' SQL_Select',syms);self.assertNotIn(b' SQL_Insert',syms);self.assertNotIn(b' SQL_CLI',syms)


 def test_fifo_map_rejected_without_opening_stream(self):
  os.mkfifo(self.table/'.table');self.runsql('select','title',ok=4)


 def provision(self,owner=None):
  return self.runsql('context','CREATE ON '+quoted(self.base)+(f' OWNER {owner}' if owner else '')).stdout.decode().strip()
 def tx(self,ctx,cmd,s='',ok=0,env=None,cwd=None):
  config=os.environ.copy();config['SQL_CONTEXT']=ctx
  if env:config.update(env)
  return self.runsql(cmd,s,ok,cwd,config)
 def test_transaction_overlay_commit_rollback(self):
  self.create();self.insert('a','old');ctx=self.provision();self.tx(ctx,'begin')
  self.tx(ctx,'update',"SET title = 'staged' ALL RECORDS")
  self.assertEqual(self.select('title'),[['old']]);self.assertEqual(json.loads(self.tx(ctx,'select','title').stdout),[['staged']])
  self.tx(ctx,'rollback');self.assertEqual(self.select('title'),[['old']])
  self.tx(ctx,'begin');self.tx(ctx,'update',"SET title = 'committed' ALL RECORDS")
  result=json.loads(self.tx(ctx,'commit','RETURNING TRANSACTION').stdout);self.assertEqual(result['outcome'],'committed');self.assertEqual(len(result['transaction']),32)
  self.assertEqual(self.select('title'),[['committed']]);self.tx(ctx,'context','CLOSE')
 def test_transaction_deferred_count_validation(self):
  self.create('(asset DIRECTORY RECORD (title TEXT NOT NULL, part TEXT [1-4]))');self.runsql('insert',"RECORD a (title,part) VALUES ('x','one')")
  ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'delete','MEMBERS part ALL MEMBERS')
  self.tx(ctx,'commit',ok=4);self.assertEqual(self.select('COUNT(part)'),[[1]])
  self.tx(ctx,'insert',"ADD TO part VALUES ('two') ALL RECORDS");self.tx(ctx,'commit');self.assertEqual(self.select('part'),[[['two']]])
 def test_transaction_deferred_not_null(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update','SET title = NULL ALL RECORDS')
  self.tx(ctx,'commit',ok=4);self.assertEqual(self.select('title'),[['hello']]);self.tx(ctx,'update',"SET title='repaired' ALL RECORDS");self.tx(ctx,'commit');self.assertEqual(self.select('title'),[['repaired']])
 def test_transaction_generation_conflict_repeatable_reads(self):
  self.create();self.insert('a','snapshot');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'select','title')
  self.runsql('update',"SET title='concurrent' ALL RECORDS")
  self.assertEqual(json.loads(self.tx(ctx,'select','title').stdout),[['snapshot']]);self.tx(ctx,'update',"SET title='staged' ALL RECORDS")
  self.tx(ctx,'commit',ok=4);self.assertEqual(self.select('title'),[['concurrent']]);self.tx(ctx,'rollback')
 def test_transaction_read_only_nested_and_missing_context(self):
  self.runsql('begin',ok=4,cwd=self.base);self.runsql('commit',ok=4,cwd=self.base);self.runsql('rollback',ok=4,cwd=self.base);self.create();self.insert('a')
  ctx=self.provision();self.tx(ctx,'commit',ok=4);self.tx(ctx,'begin','READ ONLY');self.tx(ctx,'begin',ok=4);self.tx(ctx,'update',"SET title='bad' ALL RECORDS",ok=4)
  self.tx(ctx,'context','CLOSE',ok=4);self.tx(ctx,'select','title');self.tx(ctx,'commit');self.assertEqual(self.select('title'),[['hello']])
 def test_transaction_two_table_commit(self):
  self.create();self.insert('a','one');other=self.base/'other';other.mkdir();self.runsql('create','TABLE (r DIRECTORY RECORD (title TEXT))',cwd=other);self.runsql('insert',"RECORD b (title) VALUES ('two')",cwd=other)
  ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='first' ALL RECORDS");self.tx(ctx,'update',f"{quoted(other)} SET title='second' ALL RECORDS")
  self.assertEqual(self.select('title'),[['one']]);self.assertEqual(json.loads(self.runsql('select','title',cwd=other).stdout),[['two']])
  self.tx(ctx,'commit');self.assertEqual(self.select('title'),[['first']]);self.assertEqual(json.loads(self.runsql('select','title',cwd=other).stdout),[['second']])
 def test_transaction_shared_promotion_unlink_and_delete(self):
  self.create(policy=' LINKS INTERNAL');self.insert('a','source');self.insert('b','dest');ctx=self.provision();self.tx(ctx,'begin')
  self.tx(ctx,'link',"FIELD title TO 'a/title' FROM SOURCE . WHERE record = 'b'");self.tx(ctx,'update',"SET title='common' WHERE record='b'")
  self.assertFalse((self.table/'a'/'title').is_symlink());self.tx(ctx,'commit');self.assertTrue((self.table/'a'/'title').is_symlink());self.assertEqual(self.select('title ORDER BY record'),[['common'],['common']])
  self.tx(ctx,'begin');self.tx(ctx,'unlink',"FIELD title WHERE record='a'");self.tx(ctx,'update',"SET title='private' WHERE record='a'");self.tx(ctx,'delete',"WHERE record='b'");self.tx(ctx,'commit')
  self.assertFalse((self.table/'a'/'title').is_symlink());self.assertEqual(self.select('title'),[['private']]);self.assertFalse((self.table/'b').exists())
 def test_context_exact_cwd_and_explicit_subprocess(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='staged' ALL RECORDS")
  self.runsql('select','title',cwd=self.base,ok=3)
  # Child Python gives SQL a different parent PID; explicit handle retains this session.
  code="import subprocess,sys;raise SystemExit(subprocess.run([sys.argv[1],'select','--context',sys.argv[2],'title'],cwd=sys.argv[3]).returncode)"
  p=subprocess.run(['python3','-c',code,str(SQL),ctx,str(self.table)],capture_output=True,timeout=15);self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout),[['staged']]);self.tx(ctx,'rollback')
 def test_context_implicit_exact_root_owner(self):
  self.create();self.insert('a');ctx=self.provision();self.runsql('begin','ON '+quoted(self.base),cwd=self.base)
  self.runsql('update',f"{quoted(self.table)} SET title='implicit' ALL RECORDS",cwd=self.base)
  self.assertEqual(self.select('title'),[['hello']]);self.runsql('commit',cwd=self.base);self.assertEqual(self.select('title'),[['implicit']]);self.tx(ctx,'context','CLOSE')
 def test_context_configuration_mem_replay_and_trace(self):
  self.create();self.insert('a');ctx=self.provision();tool=pathlib.Path(os.environ.get('SQL_TEST_CTXMEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_ctxmem')))
  dump=subprocess.run([str(tool),ctx],capture_output=True,check=True).stdout;self.assertIn(b'C.TraceLevel',dump);self.assertIn(b'C.PID=',dump)
  subprocess.run([str(tool),ctx,'C.TraceLevel','16777216'],check=True,capture_output=True);self.assertIn(b'SQL context',self.tx(ctx,'select','title').stderr)
  self.tx(ctx,'context','SET OUTPUT = NUL');self.assertEqual(self.tx(ctx,'select','title').stdout,b'hello\0')
  p=subprocess.run([str(tool),ctx,'C.TraceLevel','4294967296'],capture_output=True);self.assertEqual(p.returncode,2)
  p=subprocess.run([str(tool),ctx,'C.PID','1'],capture_output=True);self.assertEqual(p.returncode,2)
  script=self.base/'context-dump.sh';script.write_bytes(dump);subprocess.run(['/bin/sh',str(script)],check=True,capture_output=True)
  self.assertNotIn(b'SQL context',self.tx(ctx,'select','title').stderr);self.assertEqual(json.loads(self.tx(ctx,'select','title').stdout),[['hello']])
 def test_context_corrupt_header_refused(self):
  self.create();ctx=self.provision();p=pathlib.Path(ctx)/'.state';data=bytearray(p.read_bytes());data[4:8]=(999).to_bytes(4,'little');p.write_bytes(data);self.tx(ctx,'context','SHOW',ok=4)
 def test_context_dead_owner_cleanup(self):
  self.create();owner=subprocess.Popen(['python3','-c','import time;time.sleep(60)'])
  try:ctx=self.provision(owner.pid)
  finally:owner.terminate();owner.wait(timeout=5)
  self.tx(ctx,'context','SHOW',ok=4);p=self.runsql('context','CLEAN STALE ON '+quoted(self.base));self.assertIn(b'removed verified stale context',p.stdout);self.assertFalse(pathlib.Path(ctx).exists())
 def test_context_special_snapshot_refuses_no_pipe_open(self):
  self.create('(r DIRECTORY RECORD (title TEXT))');self.runsql('insert',"RECORD a (title) VALUES ('x')");(self.table/'a'/'title').unlink();os.mkfifo(self.table/'a'/'title');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'select','PATH(title)',ok=4);self.tx(ctx,'rollback')
 def test_coordinator_crash_recovery_boundaries(self):
  self.create();self.insert('a','old');other=self.base/'other';other.mkdir();self.runsql('create','TABLE (r DIRECTORY RECORD (title TEXT))',cwd=other);self.runsql('insert',"RECORD b (title) VALUES ('old')",cwd=other);ctx=self.provision()
  for point,exitcode in [('coordinator-before-decision',87),('coordinator-after-decision',88),('coordinator-after-first-apply',89)]:
   with self.subTest(point=point):
    self.tx(ctx,'begin');self.tx(ctx,'update',f"SET title='{point}' ALL RECORDS");self.tx(ctx,'update',f"{quoted(other)} SET title='{point}' ALL RECORDS")
    self.tx(ctx,'commit',ok=exitcode,env={'SQL_TEST_CRASH':point});self.runsql('select','title',ok=6);self.runsql('select','title',cwd=other,ok=6)
    self.runsql('recover','DATABASE '+quoted(self.base)+' ALL REPORT ONLY');self.runsql('select','title',ok=6)
    self.runsql('recover','DATABASE '+quoted(self.base)+' ALL APPLY');self.runsql('recover','DATABASE '+quoted(self.base)+' ALL APPLY')
    if exitcode==87:
     self.assertEqual(self.select('title'),[['old']]);self.tx(ctx,'rollback')
    else:
     self.assertEqual(self.select('title'),[[point]]);self.assertEqual(json.loads(self.runsql('select','title',cwd=other).stdout),[[point]])
     self.assertEqual(json.loads(self.tx(ctx,'context','SHOW').stdout)['outcome'],1)
 def test_coordinator_resumed_commit_never_false_rollback(self):
  self.create();self.insert('a','old');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='durable' ALL RECORDS")
  self.tx(ctx,'commit',ok=88,env={'SQL_TEST_CRASH':'coordinator-after-decision'});self.tx(ctx,'rollback',ok=6)
  result=json.loads(self.tx(ctx,'commit','RETURNING TRANSACTION').stdout);self.assertEqual(result['outcome'],'committed');self.assertEqual(self.select('title'),[['durable']])
 def test_coordinator_predecision_commit_retry(self):
  self.create();self.insert('a','old');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='retry' ALL RECORDS")
  self.tx(ctx,'commit',ok=87,env={'SQL_TEST_CRASH':'coordinator-before-decision'});self.tx(ctx,'commit');self.assertEqual(self.select('title'),[['retry']])
 def test_transaction_c_cpp_direct_api(self):
  self.create();self.insert('a');ctx=self.provision()
  src='#include <sql.h>\n#include <string.h>\nint main(int ac,char **av){(void)ac;SQL_Options o={0};o.cwd=av[1];o.context=av[2];SQL_Result r;int n=SQL_Begin("",&o,&r);SQL_Free(&r);if(n)return 1;n=SQL_Update("SET title=\\"direct\\" ALL RECORDS",&o,&r);SQL_Free(&r);if(n)return 2;n=SQL_Commit("",&o,&r);SQL_Free(&r);return n;}\n'
  for compiler,suffix in [('gcc','c'),('g++','cc')]:
   source=self.base/('txclient.'+suffix);source.write_text(src);exe=self.base/('txclient-'+suffix)
   libs=['-L'+str(pathlib.Path.home()/'lib'),'-lsql','-ltrigger','-lmio','-lmap','-lfar','-lnow','-lsem','-lsys','-lpthread'];subprocess.run([compiler,'-I'+str(pathlib.Path.home()/'cmn'),str(source),'-o',str(exe),*libs],check=True,capture_output=True)
   subprocess.run([str(exe),str(self.table),ctx],check=True,capture_output=True,timeout=15);self.assertEqual(self.select('title'),[['direct']])


 def test_autocommit_group_and_record_cardinality(self):
  self.create("(grouping DIRECTORY [0-1] MATCH 'g[0-9]+' (asset DIRECTORY RECORD [1-2] MATCH 'r[0-9]+' (title TEXT)))")
  self.runsql('insert',"RECORD 'g1/r1' (title) VALUES ('one')");self.runsql('insert',"RECORD 'g1/r2' (title) VALUES ('two')")
  self.runsql('insert',"RECORD 'g1/r3' (title) VALUES ('three')",ok=4);self.assertFalse((self.table/'g1'/'r3').exists())
  self.runsql('insert',"RECORD 'g2/r1' (title) VALUES ('other')",ok=4);self.assertFalse((self.table/'g2').exists())
  self.runsql('delete',"WHERE record='g1/r1'");self.runsql('delete',"WHERE record='g1/r2'",ok=4);self.assertTrue((self.table/'g1'/'r2'/'title').exists());self.runsql('check','TABLE COUNTS')
 def test_transaction_can_provision_minimum_group_records(self):
  self.create("(grouping DIRECTORY MATCH 'g[0-9]+' (asset DIRECTORY RECORD [2-3] MATCH 'r[0-9]+' (title TEXT)))")
  self.runsql('insert',"RECORD 'g1/r1' (title) VALUES ('one')",ok=4);self.assertFalse((self.table/'g1').exists());ctx=self.provision();self.tx(ctx,'begin')
  self.tx(ctx,'insert',"RECORD 'g1/r1' (title) VALUES ('one')");self.tx(ctx,'commit',ok=4);self.tx(ctx,'insert',"RECORD 'g1/r2' (title) VALUES ('two')");self.tx(ctx,'commit');self.assertEqual(len(self.select('record')),2)
 def test_record_rename_preserves_parent_group_minimum(self):
  self.create("(grouping DIRECTORY MATCH 'g[0-9]+' (asset DIRECTORY RECORD [1-2] MATCH 'r[0-9]+' (title TEXT)))")
  self.runsql('insert',"RECORD 'g1/r1' (title) VALUES ('one')");self.runsql('insert',"RECORD 'g2/r1' (title) VALUES ('two')")
  self.runsql('alter',"TABLE RENAME RECORD 'g1/r1' TO 'g2/r2'",ok=4);self.assertTrue((self.table/'g1'/'r1').is_dir());self.assertFalse((self.table/'g2'/'r2').exists())
 def test_structural_preflight_does_not_touch_unrelated_payload(self):
  self.create();self.insert('a','change');self.insert('b','untouched');p=self.table/'b'/'title';before=p.stat();digest=hashlib.sha256(p.read_bytes()).digest()
  self.runsql('update',"SET title='changed' WHERE record='a'");after=p.stat();self.assertEqual((after.st_ino,after.st_ctime_ns,after.st_mtime_ns,after.st_nlink),(before.st_ino,before.st_ctime_ns,before.st_mtime_ns,before.st_nlink));self.assertEqual(hashlib.sha256(p.read_bytes()).digest(),digest)
 def test_structural_preflight_never_opens_special_members(self):
  self.create('(asset DIRECTORY RECORD (title TEXT, pipe OCTETS [0-1]))');self.runsql('insert',"RECORD a (title) VALUES ('x')");os.mkfifo(self.table/'a'/'pipe');self.runsql('update',"SET title='safe' ALL RECORDS",ok=4);self.assertTrue(stat.S_ISFIFO((self.table/'a'/'pipe').stat().st_mode));self.assertEqual(self.select('title'),[['x']])
 def test_journal_retirement_crashes_never_replay_missing_payloads(self):
  self.create();self.insert('a','old')
  for point,exitcode in [('journal-after-retire',91),('journal-during-gc',92),('journal-after-proof-remove',93)]:
   with self.subTest(point=point):
    env=os.environ.copy();env['SQL_TEST_CRASH']=point;self.runsql('update',f"SET title='{point}' ALL RECORDS",ok=exitcode,env=env)
    self.runsql('context','RESUME '+quoted(self.table/'.context'/str(os.getpid())));self.assertEqual(self.select('title'),[[point]]);self.runsql('recover','TABLE ALL REPORT ONLY');self.runsql('recover','TABLE ALL APPLY');self.runsql('recover','TABLE ALL APPLY')
    self.assertFalse(list(self.table.glob('.sql-clean.*')));self.assertFalse(list(self.table.glob('.sql-txn.*')));self.assertEqual(self.select('title'),[[point]])
 def test_unproven_retirement_directory_is_preserved(self):
  self.create();p=self.table/('.sql-clean.'+'a'*32);p.mkdir(mode=0o700);data=p/'precious';data.write_bytes(b'not engine garbage')
  self.runsql('recover','TABLE ALL REPORT ONLY',ok=4);self.runsql('recover','TABLE ALL APPLY',ok=4);self.assertEqual(data.read_bytes(),b'not engine garbage')
 def test_malformed_journal_name_is_preserved(self):
  self.create();p=self.table/'.sql-txn.invalid';p.mkdir();data=p/'precious';data.write_bytes(b'preserve');self.runsql('select','title',ok=4);self.runsql('recover','TABLE ALL APPLY',ok=4);self.assertEqual(data.read_bytes(),b'preserve')
 def test_context_dual_slot_checksum_fallback_and_refusal(self):
  self.create();ctx=self.provision();self.tx(ctx,'context','SET LOCK_TIMEOUT = 123');self.tx(ctx,'context','SET LOCK_TIMEOUT = 456');p=pathlib.Path(ctx)/'.state';data=bytearray(p.read_bytes());slot=(len(data)-4096)//2
  sequences=[int.from_bytes(data[4096+i*slot:4104+i*slot],'little') for i in range(2)];latest=max(range(2),key=lambda i:sequences[i]);data[4096+latest*slot+24]^=0x40;p.write_bytes(data);self.tx(ctx,'context','SHOW')
  old=1-latest;data[4096+old*slot+24]^=0x40;p.write_bytes(data);self.tx(ctx,'context','SHOW',ok=4)
 def test_context_old_slot_cannot_hide_durable_commit(self):
  self.create();self.insert('a','old');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='durable' ALL RECORDS");self.tx(ctx,'commit',ok=88,env={'SQL_TEST_CRASH':'coordinator-after-decision'})
  p=pathlib.Path(ctx)/'.state';data=bytearray(p.read_bytes());slot=(len(data)-4096)//2;seq=[int.from_bytes(data[4096+i*slot:4104+i*slot],'little') for i in range(2)];latest=max(range(2),key=lambda i:seq[i]);data[4096+latest*slot+24]^=0x40;p.write_bytes(data)
  self.tx(ctx,'update',"SET title='must not disappear' ALL RECORDS",ok=6);self.tx(ctx,'commit');self.assertEqual(self.select('title'),[['durable']])
 def test_coordinator_done_reconciles_after_owner_ack_crash(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='done' ALL RECORDS");self.tx(ctx,'commit',ok=90,env={'SQL_TEST_CRASH':'coordinator-after-done'})
  self.assertEqual(self.select('title'),[['done']]);self.tx(ctx,'commit','RETURNING TRANSACTION');self.runsql('recover','DATABASE '+quoted(self.base)+' ALL APPLY');self.assertEqual(self.select('title'),[['done']])
 def test_coordinator_historical_outcome_survives_removed_table(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='committed' ALL RECORDS");self.tx(ctx,'commit');self.tx(ctx,'context','CLOSE')
  shutil.rmtree(self.table);self.runsql('recover','DATABASE '+quoted(self.base)+' ALL APPLY',cwd=self.base);self.runsql('recover','DATABASE '+quoted(self.base)+' ALL REPORT ONLY',cwd=self.base)
 def test_simultaneous_context_commits_detect_conflict(self):
  self.create();self.insert('a','old');ctx1=self.provision();owner=subprocess.Popen(['python3','-c','import time;time.sleep(60)'])
  try:
   ctx2=self.provision(owner.pid)
   for ctx,value in [(ctx1,'first'),(ctx2,'second')]:self.tx(ctx,'begin');self.tx(ctx,'update',f"SET title='{value}' ALL RECORDS")
   ps=[subprocess.Popen([str(SQL),'commit','--context',ctx,''],cwd=self.table,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for ctx in [ctx1,ctx2]]
   results=[p.communicate(timeout=15) for p in ps];self.assertEqual(sorted(p.returncode for p in ps),[0,4],results);self.assertIn(self.select('title'),[[['first']],[['second']]])
   loser=ctx1 if ps[0].returncode else ctx2;self.tx(loser,'rollback')
  finally:owner.terminate();owner.wait(timeout=5)
 def test_concurrent_commands_in_same_context_serialize(self):
  self.create();ctx=self.provision();self.tx(ctx,'begin');ps=[subprocess.Popen([str(SQL),'insert','--context',ctx,f"RECORD r{i} (title,age) VALUES ('v',{i})"],cwd=self.table,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for i in range(8)]
  for p in ps:
   out,err=p.communicate(timeout=15);self.assertEqual((p.returncode,out),(0,b''),err)
  self.assertEqual(self.select('record'),[]);self.assertEqual(len(json.loads(self.tx(ctx,'select','record').stdout)),8);self.tx(ctx,'commit');self.assertEqual(len(self.select('record')),8)
 def test_context_dump_replay_quotes_unusual_root(self):
  root=self.base/"quotes' and\nnewlines";root.mkdir();ctx=self.runsql('context','CREATE ON '+quoted(root)).stdout.decode().rstrip('\n');tool=pathlib.Path(os.environ.get('SQL_TEST_CTXMEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_ctxmem')))
  dump=subprocess.run([str(tool),ctx],capture_output=True,check=True).stdout;script=self.base/'quoted-context.sh';script.write_bytes(dump);subprocess.run(['/bin/sh',str(script)],capture_output=True,check=True);self.assertTrue(pathlib.Path(ctx).is_dir())


 def test_cross_group_rename_preserves_identity_and_shared_anchors(self):
  self.create("(grouping DIRECTORY MATCH 'g[0-9]+' (asset DIRECTORY RECORD MATCH 'r[0-9]+' (title TEXT)))",policy=' LINKS INTERNAL')
  self.runsql('insert',"RECORD 'g1/r1' (title) VALUES ('one')");self.runsql('insert',"RECORD 'g2/r1' (title) VALUES ('two')");identity=(self.table/'g1'/'r1'/'.sql-id').read_bytes()
  self.runsql('link',"FIELD title TO 'g1/r1/title' FROM SOURCE . WHERE record='g2/r1'");self.runsql('alter',"TABLE RENAME RECORD 'g1/r1' TO 'g2/r2' VALIDATE ONLY");self.assertTrue((self.table/'g1'/'r1').is_dir())
  self.runsql('alter',"TABLE RENAME RECORD 'g1/r1' TO 'g2/r2'");self.assertEqual((self.table/'g2'/'r2'/'.sql-id').read_bytes(),identity);self.runsql('update',"SET title='common' WHERE record='g2/r2'");self.assertEqual(self.select('title'),[['common'],['common']])


 def test_table_wrong_map_kind_refused_by_api_and_mem(self):
  self.create();p=self.table/'.table';data=bytearray(p.read_bytes());data[20:24]=(1).to_bytes(4,'little');p.write_bytes(data);self.runsql('select','title',ok=4)
  tool=pathlib.Path(os.environ.get('SQL_TEST_MEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_tblmem')));r=subprocess.run([str(tool),str(self.table)],capture_output=True,timeout=15);self.assertEqual((r.returncode,r.stdout),(4,b''))


 def test_coordinated_journal_gc_crashes_are_reclaimable(self):
  self.create();self.insert('a');other=self.base/'other';other.mkdir();self.runsql('create','TABLE (r DIRECTORY RECORD (title TEXT))',cwd=other);self.runsql('insert',"RECORD a (title) VALUES ('old')",cwd=other);ctx=self.provision()
  for point,exitcode in [('journal-after-retire',91),('journal-during-gc',92),('journal-after-proof-remove',93)]:
   with self.subTest(point=point):
    self.tx(ctx,'begin');self.tx(ctx,'update',f"SET title='{point}' ALL RECORDS");self.tx(ctx,'update',f"{quoted(other)} SET title='{point}' ALL RECORDS");self.tx(ctx,'commit',ok=exitcode,env={'SQL_TEST_CRASH':point})
    self.assertEqual(self.select('title'),[[point]]);self.assertEqual(json.loads(self.runsql('select','title',cwd=other).stdout),[[point]])
    self.runsql('recover','DATABASE '+quoted(self.base)+' ALL APPLY');self.assertFalse(list(self.table.glob('.sql-clean.*')));self.assertFalse(list(other.glob('.sql-clean.*')))
    self.assertEqual(json.loads(self.tx(ctx,'context','SHOW').stdout)['outcome'],1)
 def test_coordinator_predecision_io_failure_preserves_abort_proof(self):
  self.create();self.insert('a','old');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='retryable' ALL RECORDS")
  self.tx(ctx,'commit',ok=3,env={'SQL_TEST_FAIL':'coordinator-participant-prepare'});self.assertEqual(self.select('title'),[['old']]);journals=list(self.base.glob('.sql-coord.*'));self.assertEqual(len(journals),1);self.assertTrue((journals[0]/'ABORT').is_file())
  self.tx(ctx,'commit');self.assertEqual(self.select('title'),[['retryable']])
 def test_actual_file_size_resource_failures_do_not_publish_partial_maps(self):
  import resource,signal
  def restricted():signal.signal(signal.SIGXFSZ,signal.SIG_IGN);resource.setrlimit(resource.RLIMIT_FSIZE,(1024,1024))
  p=subprocess.run([str(SQL),'create','TABLE (r DIRECTORY RECORD (title TEXT))'],cwd=self.table,capture_output=True,timeout=15,preexec_fn=restricted);self.assertEqual((p.returncode,p.stdout),(3,b''),p.stderr);self.assertFalse((self.table/'.table').exists())
  # A partial context must not occupy its final constructor name.
  p=subprocess.run([str(SQL),'context','CREATE ON '+quoted(self.base)],cwd=self.table,capture_output=True,timeout=15,preexec_fn=restricted);self.assertEqual((p.returncode,p.stdout),(3,b''),p.stderr);self.assertFalse((self.base/'.context'/str(os.getpid())).exists());self.provision()
 def test_context_constructor_never_overwrites_existing_map(self):
  self.create();ctx=self.provision();before=(pathlib.Path(ctx)/'.state').read_bytes();self.runsql('context','CREATE ON '+quoted(self.base),ok=4);self.assertEqual((pathlib.Path(ctx)/'.state').read_bytes(),before)


 def test_persistent_transaction_clients_use_library_not_cli(self):
  self.create();self.insert('a');ctx=self.provision();subprocess.run(['make','examples'],cwd=UNIT,capture_output=True,check=True)
  for name in ['c-transaction','cpp-transaction']:
   exe=UNIT/'examples'/name;p=subprocess.run([str(exe),str(self.table),ctx,"direct ' bound"],capture_output=True,timeout=15);self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['outcome'],'committed');self.assertEqual(self.select('title'),[["direct ' bound"]]);symbols=subprocess.check_output(['nm',str(exe)]);self.assertNotIn(b' SQL_CLI',symbols);self.assertIn(b' SQL_Begin',symbols)


 def test_map_generation_zero_and_overflow_fail_closed(self):
  self.create();p=self.table/'.table';data=bytearray(p.read_bytes());data[24:32]=(2**64-1).to_bytes(8,'little');p.write_bytes(data);before=p.read_bytes()
  tool=pathlib.Path(os.environ.get('SQL_TEST_MEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_tblmem')));r=subprocess.run([str(tool),str(self.table),'C.TraceLevel','1'],capture_output=True,timeout=15);self.assertEqual((r.returncode,r.stdout),(0,b''));after=p.read_bytes();self.assertEqual(after[24:32],before[24:32])
  self.runsql('insert',"RECORD a (title,age) VALUES ('x',1)",ok=4);self.assertFalse((self.table/'a').exists());data[24:32]=bytes(8);p.write_bytes(data);self.runsql('select','title',ok=4)


 def makeview(self,sql='title,age',name='view'):
  path=self.base/name;self.runsql('create','VIEW '+quoted(path)+' AS SELECT '+sql);return path
 def viewtool(self):return pathlib.Path(os.environ.get('SQL_TEST_VIEWMEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_viewmem')))
 def test_views_pin_omitted_from_to_creation_cwd(self):
  self.create();self.insert('a','pinned');view=self.makeview('title AS label,age');self.assertEqual(json.loads(self.runsql('select','*',cwd=view).stdout),[['pinned',12]])
  self.assertEqual(json.loads(self.runsql('select','label FROM '+quoted(view),cwd=self.base).stdout),[['pinned']]);ddl=self.runsql('describe','VIEW '+quoted(view)+' AS DDL').stdout;self.assertIn(str(self.table).encode(),ddl);self.assertEqual(json.loads(self.runsql('show','VIEWS IN '+quoted(self.base)).stdout), 'view')
 def test_nested_views_materialize_before_outer_order_limit(self):
  self.create();self.insert('a','one',1);self.insert('b','two',2);self.insert('c','three',3);one=self.makeview('title,age ORDER BY age DESC LIMIT 2',name='one');two=self.makeview('title AS label,age FROM '+quoted(one)+' ORDER BY age ASC LIMIT 1',name='two')
  self.assertEqual(self.select('label,age FROM '+quoted(two)),[['two',2]]);self.runsql('select','title FROM '+quoted(two),ok=2)
 def test_view_aliases_literals_binary_null_boolean(self):
  self.create('(r DIRECTORY RECORD (title TEXT, data OCTETS, truth BOOL, number UINT64))');data=self.base/'bytes';data.write_bytes(b'\0\xff');self.runsql('insert',f"RECORD a (title,data,truth,number) VALUES (NULL,FILE({quoted(data)}),TRUE,18446744073709551615)")
  view=self.makeview('title,data,truth,number,COUNT(data) AS total,TRUE AS literal');row=self.select('* FROM '+quoted(view));self.assertEqual(row,[[None,{'$hex':data.read_bytes().hex()},True,18446744073709551615,1,True]])
  self.assertEqual(self.runsql('select','data FROM '+quoted(view)+' OUTPUT RAW').stdout,data.read_bytes());self.runsql('select','title FROM '+quoted(view)+' OUTPUT NUL',ok=4)
 def test_view_collections_any_all_count_and_content(self):
  self.create('(r DIRECTORY RECORD (parts TEXT [0-]))');self.runsql('insert',"RECORD a (parts,parts) VALUES ('x','y')")
  self.runsql('insert','RECORD b () VALUES ()');view=self.makeview('record,parts')
  self.assertEqual(self.select('record,COUNT(parts) FROM '+quoted(view)+' ORDER BY record'),[['a',2],['b',0]])
  self.assertEqual(self.select("record FROM "+quoted(view)+" WHERE ANY(parts,parts='y')"),[['a']]);self.assertEqual(self.select("record FROM "+quoted(view)+" WHERE ALL(parts,parts='x')"),[['b']]);self.assertEqual(self.select('CONTENT(parts) FROM '+quoted(view)),[['x'],['y']])
 def test_view_exposes_only_projected_columns_and_metadata(self):
  self.create();self.insert('a');view=self.makeview('title AS label')
  for projection in ['age','record','fs.mode','PATH(label)']:self.runsql('select',projection+' FROM '+quoted(view),ok=2)
  physical=self.makeview('PATH(title) AS filename,fs.type AS kind',name='metadata');self.assertEqual(self.select('filename,kind FROM '+quoted(physical)),[[str(self.table/'a'/'title'),'f']])
 def test_view_read_only_all_mutation_paths(self):
  self.create();self.insert('a');view=self.makeview();before=(view/'.view').read_bytes()
  for cmd,sql in [('insert',"RECORD b (title,age) VALUES ('bad',1)"),('update',"SET title='bad' ALL RECORDS"),('delete','ALL RECORDS'),('link',"FIELD title TO 'a/title' FROM SOURCE . ALL RECORDS"),('unlink','FIELD title ALL RECORDS'),('alter','TABLE RENAME RECORD a TO b'),('drop','TABLE')]:self.runsql(cmd,sql,cwd=view,ok=4)
  self.assertEqual((view/'.view').read_bytes(),before);self.assertEqual(self.select('title'),[['hello']]);self.runsql('define','TABLE (r DIRECTORY RECORD (x TEXT)) UNMATCHED IGNORE',cwd=view,ok=4)
 def test_view_describe_ddl_replay_define_and_drop(self):
  self.create();self.insert('a');view=self.makeview();ddl=self.runsql('describe','VIEW '+quoted(view)+' AS DDL').stdout.decode().strip();other=self.base/'other-view';other.mkdir();self.runsql('define',ddl,cwd=other);self.assertEqual(self.select('title FROM '+quoted(other)),[['hello']]);self.runsql('check','VIEW '+quoted(other));self.runsql('drop','VIEW '+quoted(other)+' VALIDATE ONLY');self.assertTrue((other/'.view').exists());self.runsql('drop','VIEW '+quoted(other));self.assertFalse((other/'.view').exists());self.assertTrue((self.table/'a'/'title').exists())
 def test_view_no_overwrite_bad_query_or_ambiguous_columns(self):
  self.create();self.insert('a');path=self.base/'missing-view';self.runsql('create','VIEW '+quoted(path)+' AS SELECT missing',ok=2);self.assertFalse(path.exists());self.runsql('create','VIEW '+quoted(path)+' AS SELECT title,title',ok=4);self.assertFalse(path.exists())
  self.runsql('create','VIEW '+quoted(path)+' AS SELECT title OUTPUT RAW',ok=2);view=self.makeview();before=(view/'.view').read_bytes();self.runsql('create','VIEW '+quoted(view)+' AS SELECT title',ok=4);self.assertEqual((view/'.view').read_bytes(),before)
 def test_view_source_identity_cannot_silently_retarget(self):
  self.create();self.insert('a','original');view=self.makeview();saved=self.base/'original-table';self.table.rename(saved);self.table.mkdir();self.create();self.insert('a','imposter');self.runsql('select','* FROM '+quoted(view),ok=4);self.assertEqual((saved/'a'/'title').read_text(),'original')
 def test_view_map_header_type_and_version_refusal(self):
  self.create();view=self.makeview();p=view/'.view';original=p.read_bytes();bad=bytearray(original);bad[4:8]=(999).to_bytes(4,'little');p.write_bytes(bad);self.runsql('select','* FROM '+quoted(view),ok=4);tool=self.viewtool();r=subprocess.run([str(tool),str(view)],capture_output=True,timeout=15);self.assertEqual((r.returncode,r.stdout),(4,b''));p.unlink();os.mkfifo(p);self.runsql('select','* FROM '+quoted(view),ok=4)
 def test_viewmem_dump_replay_live_trace_and_validated_query(self):
  self.create();self.insert('a','quotes');view=self.makeview("title AS label,age WHERE title='quotes'",name="view ' quoted")
  tool=self.viewtool();dump=subprocess.run([str(tool),str(view)],check=True,capture_output=True).stdout;self.assertIn(b'C.Query',dump);self.assertIn(b'C.Source=',dump);before=(view/'.view').stat().st_ino
  subprocess.run([str(tool),str(view),'C.TraceLevel','16777216'],capture_output=True,check=True);self.assertEqual((view/'.view').stat().st_ino,before);self.assertIn(b'SQL view',self.runsql('select','* FROM '+quoted(view)).stderr)
  script=self.base/'view-replay';script.write_bytes(dump);subprocess.run(['/bin/sh',str(script)],check=True,capture_output=True);self.assertNotIn(b'SQL view',self.runsql('select','* FROM '+quoted(view)).stderr)
  r=subprocess.run([str(tool),str(view),'C.Query','title,title'],capture_output=True,cwd=self.table);self.assertEqual(r.returncode,4);self.assertEqual(self.select('label FROM '+quoted(view)),[['quotes']])
  subprocess.run([str(tool),str(view),'C.Query','age AS years'],capture_output=True,check=True,cwd=self.table);self.assertEqual(self.select('years FROM '+quoted(view)),[[12]])
 def test_viewmem_long_query_and_cycle_refusal(self):
  self.create();self.insert('a');value='q'*1200;view=self.makeview(quoted(value)+' AS literal,title');tool=self.viewtool();dump=subprocess.run([str(tool),str(view)],capture_output=True,check=True).stdout;script=self.base/'long-view';script.write_bytes(dump);subprocess.run(['/bin/sh',str(script)],capture_output=True,check=True);self.assertEqual(self.select('literal FROM '+quoted(view)),[[value]])
  r=subprocess.run([str(tool),str(view),'C.Query','* FROM '+quoted(view)],capture_output=True,timeout=15);self.assertEqual(r.returncode,4);self.assertIn(b'cyclic',r.stderr)
 def test_views_participate_in_staged_transactions_and_conflicts(self):
  self.create();self.insert('a','old');view=self.makeview('title AS label');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'select','label FROM '+quoted(view));self.tx(ctx,'update',"SET title='staged' ALL RECORDS");self.assertEqual(self.select('label FROM '+quoted(view)),[['old']]);self.assertEqual(json.loads(self.tx(ctx,'select','label FROM '+quoted(view)).stdout),[['staged']]);self.tx(ctx,'commit');self.assertEqual(self.select('label FROM '+quoted(view)),[['staged']])
  self.tx(ctx,'begin');self.tx(ctx,'select','label FROM '+quoted(view));subprocess.run([str(self.viewtool()),str(view),'C.Query','age AS years'],capture_output=True,check=True,cwd=self.table);self.assertEqual(json.loads(self.tx(ctx,'select','label FROM '+quoted(view)).stdout),[['staged']]);self.tx(ctx,'commit',ok=4);self.tx(ctx,'rollback')
 def test_trace_pointer_real_maps_nested_live_mem_and_api_restore(self):
  self.create();self.insert('a');other=self.base/'other';other.mkdir();self.runsql('create','TABLE (r DIRECTORY RECORD (title TEXT))',cwd=other);view=self.makeview('title');ctx=self.provision();exe=pathlib.Path(os.environ.get('SQL_TEST_TRACE_EXECUTABLE',str(self.base/'trace-scope')))
  libraries=['-L'+str(pathlib.Path.home()/'lib'),'-lsql','-ltrigger','-lmio','-lmap','-lfar','-lnow','-lsem','-lsys','-lpthread']
  if not os.environ.get('SQL_TEST_TRACE_EXECUTABLE'):subprocess.run(['gcc','-I'+str(UNIT),'-I'+str(pathlib.Path.home()/'cmn'),str(UNIT/'tests'/'trace_scope.c'),'-o',str(exe),*libraries],check=True,capture_output=True)
  tabletool=pathlib.Path(os.environ.get('SQL_TEST_MEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_tblmem')));ctxtool=pathlib.Path(os.environ.get('SQL_TEST_CTXMEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_ctxmem')))
  for state in ['idle','active']:
   with self.subTest(state=state):
    if state=='active':self.tx(ctx,'begin')
    p=subprocess.run([str(exe),str(self.table),ctx,str(tabletool),str(ctxtool),str(other),str(view),str(self.viewtool())],capture_output=True,timeout=15);self.assertEqual(p.returncode,0,p.stderr);self.assertIn(b'TRACE_SCOPE_OK',p.stdout)
    if state=='active':self.tx(ctx,'rollback')
 def test_transaction_commit_preserves_live_trace_without_false_writes(self):
  self.create();self.insert('a');view=self.makeview('title');ctx=self.provision();tabletool=pathlib.Path(os.environ.get('SQL_TEST_MEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_tblmem')))
  self.tx(ctx,'begin','READ ONLY');self.tx(ctx,'select','title FROM '+quoted(view));maps=[self.table/'.table',view/'.view'];before=[x.read_bytes()[24:32] for x in maps]
  for tool,path in [(tabletool,self.table),(self.viewtool(),view)]:subprocess.run([str(tool),str(path),'C.TraceLevel','16777216'],check=True,capture_output=True)
  self.tx(ctx,'commit');self.assertEqual([x.read_bytes()[24:32] for x in maps],before)
  for path in maps:self.assertEqual(int.from_bytes(path.read_bytes()[16:20],'little'),16777216)
  self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='staged' ALL RECORDS");subprocess.run([str(tabletool),str(self.table),'C.TraceLevel','0'],check=True,capture_output=True);self.tx(ctx,'commit');self.assertEqual(self.select('title'),[['staged']]);self.assertEqual(int.from_bytes(maps[0].read_bytes()[16:20],'little'),0)



 def test_context_owner_with_whitespace_and_parens_comm(self):
  self.create();code="""import ctypes,json,os,subprocess,sys
ctypes.CDLL(None).prctl(15,b'odd ) owner x',0,0,0)
sql,root=sys.argv[1:];p=subprocess.run([sql,'context','CREATE ON '+repr(root)],cwd=root,capture_output=True);assert p.returncode==0,p.stderr
ctx=p.stdout.decode().strip();p=subprocess.run([sql,'context','SHOW'],cwd=root,capture_output=True);assert p.returncode==0,p.stderr
print(json.dumps({'context':ctx,'pid':os.getpid(),'show':json.loads(p.stdout)}))
"""
  p=subprocess.run(['python3','-c',code,str(SQL),str(self.base)],capture_output=True,timeout=15);self.assertEqual(p.returncode,0,p.stderr);info=json.loads(p.stdout);self.assertEqual(pathlib.Path(info['show']['context']).name,str(info['pid']));self.runsql('context','CLEAN STALE ON '+quoted(self.base));self.assertFalse(pathlib.Path(info['context']).exists())
 def test_context_deep_ancestry_bounded_legacy_guard(self):
  self.create();code="""import os,subprocess,sys
sql,root=sys.argv[1:]
for i in range(36):
 child=os.fork()
 if child:
  _,status=os.waitpid(child,0);os._exit(os.waitstatus_to_exitcode(status))
p=subprocess.run([sql,'context','CREATE ON '+repr(root)],cwd=root,capture_output=True);assert p.returncode==0,p.stderr
p=subprocess.run([sql,'context','SHOW'],cwd=root,capture_output=True);assert p.returncode==0,p.stderr
print(p.stdout.decode().strip(),flush=True)
"""
  p=subprocess.run(['python3','-c',code,str(SQL),str(self.base)],capture_output=True,timeout=15);self.assertEqual(p.returncode,0,p.stderr);self.assertIn('context',json.loads(p.stdout));self.runsql('context','CLEAN STALE ON '+quoted(self.base))
 def test_context_reparent_stops_inheritance_but_not_explicit_or_cleanup(self):
  self.create();self.insert('a');p=subprocess.run(['python3',str(UNIT/'tests'/'context_reparent.py'),str(SQL),str(self.base),str(self.table)],capture_output=True,timeout=20);self.assertEqual(p.returncode,0,p.stderr);info=json.loads(p.stdout);self.assertEqual(info['implicit'],4);self.assertIn('lineage changed',info['diagnostic']);self.assertEqual((info['explicit'],info['clean'],info['kept'],info['commit']),(4,0,True,0));self.assertEqual(self.select('title'),[['reparented']]);self.runsql('context','CLEAN STALE ON '+quoted(self.base));self.assertFalse(pathlib.Path(info['context']).exists())
 def test_cleanup_preserves_live_descendant_context_mapping(self):
  self.create();exe=self.base/'context-holder';subprocess.run(['gcc','-I'+str(UNIT),'-I'+str(pathlib.Path.home()/'cmn'),str(UNIT/'tests'/'context_holder.c'),'-o',str(exe),'-L'+str(pathlib.Path.home()/'lib'),'-lsql','-ltrigger','-lmio','-lmap','-lfar','-lnow','-lsem','-lsys','-lpthread'],check=True,capture_output=True)
  libc=ctypes.CDLL(None);old=ctypes.c_int();self.assertEqual(libc.prctl(37,ctypes.byref(old),0,0,0),0);self.assertEqual(libc.prctl(36,1,0,0,0),0)
  code="import os,pathlib,subprocess,sys,time;root,exe=sys.argv[1:];sys.stdin.readline();subprocess.Popen([exe,str(pathlib.Path(root)/'.context'/str(os.getpid()))],stdin=sys.stdin,stdout=sys.stdout);time.sleep(60)"
  owner=subprocess.Popen(['python3','-c',code,str(self.base),str(exe)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);holder=None
  try:
   ctx=self.provision(owner.pid);owner.stdin.write(b'start\n');owner.stdin.flush();line=owner.stdout.readline();self.assertTrue(line.startswith(b'READY '),line);holder=int(line.split()[1]);owner.terminate();owner.wait(timeout=5)
   p=self.runsql('context','CLEAN STALE ON '+quoted(self.base));self.assertIn(b'preserved busy context',p.stdout);self.assertTrue(pathlib.Path(ctx).exists());owner.stdin.write(b'exit\n');owner.stdin.flush();self.assertEqual(owner.stdout.readline().strip(),b'HOLDER_CLOSED');_,status=os.waitpid(holder,0);holder=None;self.assertEqual(status,0)
   self.runsql('context','CLEAN STALE ON '+quoted(self.base));self.assertFalse(pathlib.Path(ctx).exists())
  finally:
   if owner.poll() is None:owner.terminate();owner.wait(timeout=5)
   if holder:
    try:os.kill(holder,15);os.waitpid(holder,0)
    except ProcessLookupError:pass
   owner.stdin.close();owner.stdout.close();owner.stderr.close();libc.prctl(36,old.value,0,0,0)
 def test_cleanup_resolves_dead_owner_durable_decision_before_unlink(self):
  self.create();self.insert('a');owner=subprocess.Popen(['python3','-c','import time;time.sleep(60)'])
  try:
   ctx=self.provision(owner.pid);self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='durable orphan' ALL RECORDS");self.tx(ctx,'commit',ok=88,env={'SQL_TEST_CRASH':'coordinator-after-decision'})
  finally:owner.terminate();owner.wait(timeout=5)
  self.runsql('select','title',ok=6);self.assertTrue(pathlib.Path(ctx).exists());p=self.runsql('context','CLEAN STALE ON '+quoted(self.base));self.assertIn(b'preserved recoverable context',p.stdout);self.runsql('select','title',ok=6)
  info=json.loads(self.runsql('show','CONTEXTS ON '+quoted(self.base)).stdout);self.assertEqual(info['state'],2);self.assertFalse(info['owner_live']);self.runsql('recover','DATABASE '+quoted(self.base)+' ALL APPLY');self.assertEqual(self.select('title'),[['durable orphan']]);self.assertTrue(pathlib.Path(ctx).exists())

 def test_context_legacy_ancestry_requires_explicit_optin_not_first_one(self):
  self.create();ctx=self.provision();path=pathlib.Path(ctx)/'.state';data=bytearray(path.read_bytes());slot=(len(data)-4096)//2
  # v2 payload offsets 52/56 were reserved, now version/hash. Keep valid CRCs.
  for i in range(2):
   off=4096+i*slot;sequence=int.from_bytes(data[off:off+8],'little')
   if not sequence:continue
   data[off+16+52:off+16+64]=bytes(12);size=int.from_bytes(data[off+16+8:off+16+12],'little');h=1469598103934665603
   for value in data[off:off+8]+data[off+16:off+16+size]:h=((h^value)*1099511628211)&((1<<64)-1)
   data[off+8:off+16]=h.to_bytes(8,'little')
  path.write_bytes(data);self.runsql('context','SHOW',cwd=self.base,ok=4);self.assertTrue(path.exists());self.tx(ctx,'context','SHOW',ok=4);self.runsql('context','RESUME '+quoted(ctx));self.runsql('context','SHOW',cwd=self.base)


 def test_context_stages_entire_file_bytes_not_mutable_source_paths(self):
  self.create();old=self.base/'old-input';old.write_bytes(b'old');self.runsql('insert',f"RECORD a (title,age,blob) VALUES ('before',12,FILE({quoted(old)}))")
  ctx=self.provision();self.tx(ctx,'begin');source=self.base/'new-input';data=b'\x00\xff\n'+bytes(range(256))*256;source.write_bytes(data);self.tx(ctx,'update',f'SET blob=FILE({quoted(source)}) ALL RECORDS');source.write_bytes(b'changed');source.unlink()
  self.assertEqual(self.runsql('select','blob OUTPUT RAW').stdout,b'old');self.assertEqual(self.tx(ctx,'select','blob OUTPUT RAW').stdout,data);self.tx(ctx,'commit');self.assertEqual(self.runsql('select','blob OUTPUT RAW').stdout,data)
 def test_crash_between_commands_leaves_context_owned_images_and_links(self):
  self.create(policy=' LINKS INTERNAL');self.insert('a','old');self.insert('b','private');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'link',"FIELD title TO 'a/title' FROM SOURCE . WHERE record='b'");self.tx(ctx,'update',"SET title='durable staged' ALL RECORDS",ok=86,env={'SQL_TEST_CRASH':'after-decision'})
  self.assertEqual(self.select('title ORDER BY record'),[['old'],['private']]);self.tx(ctx,'select','title',ok=6);self.tx(ctx,'recover','TABLE ALL APPLY');self.assertEqual(json.loads(self.tx(ctx,'select','title ORDER BY record').stdout),[['durable staged'],['durable staged']]);self.tx(ctx,'commit');self.assertTrue((self.table/'a'/'title').is_symlink());self.assertEqual(self.select('title ORDER BY record'),[['durable staged'],['durable staged']])
 def test_show_contexts_checked_scoped_identity_and_busy_status(self):
  self.create();ctx=self.provision();info=json.loads(self.runsql('show','CONTEXTS ON '+quoted(self.base)).stdout);self.assertEqual(info['owner_pid'],os.getpid());self.assertTrue(info['owner_live']);self.assertTrue(info['inheritance_valid']);self.assertEqual(info['context'],ctx)
  bad=self.base/'not-a-root';bad.mkdir();self.runsql('show','CONTEXTS ON '+quoted(bad),ok=3);self.runsql('show','CONTEXTS',ok=2)


 def test_cli_refuses_lossy_argument_rejoining(self):
  self.create();self.insert('a');p=subprocess.run([str(SQL),'update','SET',"title='must not execute'",'ALL RECORDS'],cwd=self.table,capture_output=True);self.assertEqual(p.returncode,2);self.assertEqual(p.stdout,b'');self.assertEqual(self.select('title'),[['hello']])


 def test_restrict_refuses_live_dependents(self):
  self.create();self.insert('a');view=self.makeview('title');self.runsql('drop','TABLE RESTRICT',ok=4);self.runsql('drop','TABLE',ok=4);self.runsql('drop','VIEW '+quoted(view)+' RESTRICT VALIDATE ONLY');self.runsql('drop','TABLE CASCADE',ok=7);self.assertTrue((self.table/'.table').exists());self.assertTrue((view/'.view').exists());self.assertEqual(self.select('title FROM '+quoted(view)),[['hello']])
 def test_ambiguous_view_and_table_definitions_refuse_data_access(self):
  self.create();self.insert('a');view=self.makeview('title');(view/'.table').write_bytes((self.table/'.table').read_bytes());self.runsql('select','* FROM '+quoted(view),ok=4);self.runsql('update',"SET title='never' ALL RECORDS",cwd=view,ok=4);self.assertEqual(self.select('title'),[['hello']])


 def inspect_context(self,ctx):return json.loads(self.runsql('context','INSPECT '+quoted(ctx)).stdout)
 def ctxtool(self,*args):
  tool=os.environ.get('SQL_TEST_CTXMEM_EXECUTABLE',str(pathlib.Path.home()/'bin'/'sql_ctxmem'))
  return subprocess.run([tool,*map(str,args)],cwd=self.table,capture_output=True,timeout=15)
 def test_workspace_private_central_layout(self):
  self.create();ctx=pathlib.Path(self.provision());self.assertEqual(ctx,self.base/'.context'/str(os.getpid()));self.assertTrue((ctx/'.state').is_file());self.assertTrue((ctx/'tables').is_dir())
  for p in (ctx.parent,ctx,ctx/'.state',ctx/'tables'):self.assertEqual(stat.S_IMODE(p.stat().st_mode)&0o077,0)
 def test_workspace_complete_pending_tree_and_inode_adoption(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title = 'new complete bytes' ALL RECORDS");staged=pathlib.Path(ctx)/'tables'/'0'/'a'/'title';self.assertEqual(staged.read_bytes(),b'new complete bytes');inode=staged.stat().st_ino;self.assertEqual((self.table/'a'/'title').read_bytes(),b'hello');self.tx(ctx,'commit');self.assertEqual((self.table/'a'/'title').stat().st_ino,inode)
 def test_workspace_inputs_do_not_depend_on_original_file(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');payload=self.base/'input';data=bytes(range(256))+b'\0exact';payload.write_bytes(data);self.tx(ctx,'insert',f'ADD TO blob VALUES (FILE({quoted(payload)})) ALL RECORDS');self.assertEqual(self.inspect_context(ctx)['inputs'],1);files=list((pathlib.Path(ctx)/'inputs').glob('*/*'));self.assertEqual(len(files),1);self.assertEqual(files[0].read_bytes(),data);payload.unlink();self.tx(ctx,'commit');self.assertEqual(self.runsql('select','blob OUTPUT RAW').stdout,data)
 def test_workspace_full_active_text_and_typed_binding_frame(self):
  self.create();ctx=self.provision();value="quotes ' \" newline\n and ; $(never-run)";text='RECORD a (title,age) VALUES (:v,:n)';env=dict(os.environ,SQL_CONTEXT=ctx);p=subprocess.run([str(SQL),'insert','--bind','v','TEXT',value,'--bind','n','INT64','23',text],cwd=self.table,env=env,capture_output=True);self.assertEqual(p.returncode,0,p.stderr);frame=self.inspect_context(ctx);self.assertEqual((frame['verb'],frame['sql'],frame['phase']),('insert',text,4));self.assertEqual(bytes.fromhex(frame['bindings'][0]['hex']),value.encode());self.assertEqual(bytes.fromhex(frame['bindings'][1]['hex']),b'23');self.assertEqual(frame['bindings'][0]['length'],len(value.encode()));listing=self.runsql('show','CONTEXTS ON '+quoted(self.base)).stdout;self.assertNotIn(value.encode(),listing)
 def test_workspace_command_text_bound_no_truncation_or_effects(self):
  self.create();self.insert('a');ctx=self.provision();prior=self.inspect_context(ctx);self.tx(ctx,'update',"SET title = 'bad' ALL RECORDS"+' '*65536,ok=4);self.assertEqual(self.inspect_context(ctx),prior);self.assertEqual(self.select('title'),[['hello']])
 def test_workspace_binding_bound_refuses_before_insert(self):
  self.create();ctx=self.provision();p=subprocess.run([str(SQL),'insert','--bind','v','TEXT','x'*65537,'RECORD a (title,age) VALUES (:v,1)'],cwd=self.table,env=dict(os.environ,SQL_CONTEXT=ctx),capture_output=True);self.assertEqual(p.returncode,4,p.stderr);self.assertEqual(p.stdout,b'');self.assertFalse((self.table/'a').exists())
 def test_workspace_accepted_and_executing_crash_retained(self):
  self.create();ctx=self.provision()
  for point,code,phase in [('command-accepted',94,1),('command-executing',95,2)]:
   env=dict(os.environ,SQL_CONTEXT=ctx,SQL_TEST_CRASH=point);self.runsql('insert',f"RECORD {quoted(point)} (title,age) VALUES ('never implicitly replay',1)",ok=code,env=env);self.assertEqual(self.inspect_context(ctx)['phase'],phase);self.assertFalse((self.table/point).exists());self.tx(ctx,'select','title',ok=6);self.assertEqual(self.runsql('context','RESUME '+quoted(ctx)).stdout.decode().strip(),ctx);self.assertEqual(self.inspect_context(ctx)['phase'],5);self.assertFalse((self.table/point).exists())
 def test_workspace_local_decision_resume_never_duplicates_insert(self):
  self.create();ctx=self.provision();env=dict(os.environ,SQL_CONTEXT=ctx,SQL_TEST_CRASH='after-decision');self.runsql('insert',"RECORD a (title,age) VALUES ('once',1)",ok=86,env=env);self.assertEqual(self.inspect_context(ctx)['phase'],3);self.runsql('context','RESUME '+quoted(ctx));self.assertEqual(self.inspect_context(ctx)['phase'],4);self.assertEqual(self.select('title'),[['once']]);self.runsql('context','RESUME '+quoted(ctx));self.assertEqual(self.select('title'),[['once']])
 def test_workspace_root_local_decision_resume_lock_order(self):
  self.create();ctx=str(self.table/'.context'/str(os.getpid()));self.runsql('insert',"RECORD a (title,age) VALUES ('same root',1)",ok=86,env=dict(os.environ,SQL_CONTEXT=ctx,SQL_TEST_CRASH='after-decision'));self.runsql('context','RESUME '+quoted(ctx));self.assertEqual(self.select('title'),[['same root']])
 def test_workspace_persisted_full_lineage_readonly_mem(self):
  self.create();ctx=self.provision();dump=self.ctxtool(ctx);self.assertEqual(dump.returncode,0,dump.stderr);self.assertIn(f'C.Lineage[0].PID={os.getpid()}'.encode(),dump.stdout);self.assertIn(b'C.Lineage[1].PID=',dump.stdout);self.assertNotEqual(self.ctxtool(ctx,'C.Lineage[0].PID','1').returncode,0);self.assertNotEqual(self.ctxtool(ctx,'--offline','C.Command.Phase','4').returncode,0)
 def test_workspace_command_mem_dump_replay_is_not_execution(self):
  self.create();ctx=self.provision();text="RECORD a (title,age) VALUES ('a quote '' and newline\n',1)";self.tx(ctx,'insert',text);dump=self.ctxtool(ctx);self.assertEqual(dump.returncode,0,dump.stderr);self.assertIn(b'--offline C.Command.Text ',dump.stdout);p=subprocess.run(['/bin/sh','-eu'],input=dump.stdout,cwd=self.table,capture_output=True);self.assertEqual(p.returncode,0,p.stderr);frame=self.inspect_context(ctx);self.assertEqual(frame['sql'],text);self.assertEqual(frame['phase'],0);self.assertEqual(self.select('age'),[[1]])
 def test_workspace_binding_mem_dump_replay_exact_bytes(self):
  self.create();ctx=self.provision();text='RECORD a (title,age) VALUES (:v,:n)';p=subprocess.run([str(SQL),'insert','--bind','v','TEXT',"q'\nbytes",'--bind','n','INT64','-5',text],cwd=self.table,env=dict(os.environ,SQL_CONTEXT=ctx),capture_output=True);self.assertEqual(p.returncode,0,p.stderr);frame=self.inspect_context(ctx);dump=self.ctxtool(ctx);p=subprocess.run(['/bin/sh','-eu'],input=dump.stdout,cwd=self.table,capture_output=True);self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.inspect_context(ctx)['bindings'],frame['bindings']);self.assertEqual(self.select('age'),[[-5]])
 def test_workspace_show_staged_transaction_discovery(self):
  self.create();ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'insert',"RECORD a (title,age) VALUES ('pending',1)");p=self.runsql('show','TRANSACTIONS ON '+quoted(self.base));self.assertIn(b'context',p.stdout);self.assertIn(str(os.getpid()).encode(),p.stdout);self.assertTrue((pathlib.Path(ctx)/'tables'/'0'/'a'/'title').is_file());self.tx(ctx,'rollback');self.assertFalse((self.table/'a').exists())


 def workspace_fixture(self,mode,ctx,*args):
  exe=self.base/'workspace-fixture'
  if not exe.exists():subprocess.run(['gcc','-I'+str(UNIT),'-I'+str(pathlib.Path.home()/'cmn'),str(UNIT/'tests/workspace_fixture.c'),'-o',str(exe),'-L'+str(pathlib.Path.home()/'lib'),'-lsql','-ltrigger','-lmio','-lmap','-lfar','-lnow','-lsem','-lsys','-lpthread'],check=True,capture_output=True)
  p=subprocess.run([str(exe),mode,ctx,*map(str,args)],capture_output=True,timeout=15);self.assertEqual(p.returncode,0,p.stderr)
 def test_workspace_simulated_prior_boot_preserves_data_and_rebinds(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title = 'prior boot pending' ALL RECORDS");self.workspace_fixture('boot',ctx);self.tx(ctx,'select','title',ok=4);listing=self.runsql('show','CONTEXTS ON '+quoted(self.base));self.assertIn(b'prior-boot',listing.stdout);self.runsql('context','CREATE ON '+quoted(self.base),ok=4);self.assertEqual((pathlib.Path(ctx)/'tables/0/a/title').read_bytes(),b'prior boot pending');self.runsql('context','RESUME '+quoted(ctx));self.tx(ctx,'commit');self.assertEqual(self.select('title'),[['prior boot pending']])
 def test_workspace_simulated_pid_reuse_does_not_inherit(self):
  self.create();ctx=self.provision();self.workspace_fixture('birth',ctx);self.tx(ctx,'select','title',ok=4);self.runsql('context','CREATE ON '+quoted(self.base),ok=4);self.assertTrue(pathlib.Path(ctx).is_dir());self.runsql('context','RESUME '+quoted(ctx));self.tx(ctx,'select','title')
 def test_workspace_independent_saved_ancestor_validation(self):
  self.create();ctx=self.provision();self.workspace_fixture('lineage',ctx);self.tx(ctx,'select','title',ok=4);p=self.runsql('show','CONTEXTS ON '+quoted(self.base));self.assertIn(b'changed',p.stdout);p=self.ctxtool(ctx,'C.TraceLevel','1');self.assertEqual(p.returncode,4,p.stderr);self.runsql('context','RESUME '+quoted(ctx));self.tx(ctx,'select','title')
 def dead_workspace(self):
  code=r"""
import json,os,subprocess,sys
sql,root,table=sys.argv[1:]
def run(verb,text='',ctx=None):
 p=subprocess.run([sql,verb,text],cwd=table,env=dict(os.environ,**({'SQL_CONTEXT':ctx} if ctx else {})),capture_output=True);assert p.returncode==0,p.stderr;return p.stdout.decode().strip()
q=lambda x:"'"+x.replace("'","''")+"'"
ctx=run('context','CREATE ON '+q(root));run('begin','',ctx);run('update',"SET title = 'dead owner pending' ALL RECORDS",ctx);print(json.dumps(ctx))
"""
  p=subprocess.run(['python3','-c',code,str(SQL),str(self.base),str(self.table)],capture_output=True,timeout=15);self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
 def test_workspace_dead_owner_resume_new_pid_and_bytes(self):
  self.create();self.insert('a');old=self.dead_workspace();self.runsql('context','CLEAN STALE ON '+quoted(self.base));self.assertTrue(pathlib.Path(old).is_dir());new=self.runsql('context','RESUME '+quoted(old)).stdout.decode().strip();self.assertEqual(new,str(self.base/'.context'/str(os.getpid())));self.assertFalse(pathlib.Path(old).exists());self.assertEqual((pathlib.Path(new)/'tables/0/a/title').read_bytes(),b'dead owner pending');self.tx(new,'commit');self.assertEqual(self.select('title'),[['dead owner pending']])
 def rebind_crash_case(self,point,code):
  self.create();self.insert('a');old=self.dead_workspace();self.runsql('context','RESUME '+quoted(old),ok=code,env=dict(os.environ,SQL_TEST_CRASH=point));new=str(self.base/'.context'/str(os.getpid()));handle=old if point=='rebind-before-move' else new;self.assertTrue((pathlib.Path(handle)/'.rebind').is_file());self.runsql('context','RESUME '+quoted(handle));self.assertFalse((pathlib.Path(new)/'.rebind').exists());self.tx(new,'commit');self.assertEqual(self.select('title'),[['dead owner pending']])
 def test_workspace_rebind_crash_before_move(self):self.rebind_crash_case('rebind-before-move',96)
 def test_workspace_rebind_crash_after_move(self):self.rebind_crash_case('rebind-after-move',97)
 def test_workspace_rebind_crash_after_state(self):self.rebind_crash_case('rebind-after-state',98)
 def test_workspace_resume_target_collision_preserves_both(self):
  self.create();self.insert('a');old=self.dead_workspace();own=self.provision();before=(pathlib.Path(own)/'.state').read_bytes();self.runsql('context','RESUME '+quoted(old),ok=4);self.assertEqual((pathlib.Path(own)/'.state').read_bytes(),before);self.assertEqual((pathlib.Path(old)/'tables/0/a/title').read_bytes(),b'dead owner pending')
 def legacy_context(self,active=False):
  self.create();self.insert('a');ctx=self.provision()
  if active:self.tx(ctx,'begin');self.tx(ctx,'update',"SET title = 'legacy exact pending' ALL RECORDS")
  legacy=self.base/('.context_'+str(os.getpid()));self.workspace_fixture('legacy',ctx,legacy);shutil.rmtree(ctx);return str(legacy)
 def test_workspace_legacy_idle_migration_is_explicit(self):
  old=self.legacy_context();self.tx(old,'select','title',ok=4);ctx=self.runsql('context','MIGRATE '+quoted(old)).stdout.decode().strip();self.assertTrue((pathlib.Path(ctx)/'.legacy-state').is_file());self.assertFalse(pathlib.Path(old).exists());self.tx(ctx,'select','title')
 def test_workspace_legacy_active_migration_keeps_full_images(self):
  old=self.legacy_context(True);original=pathlib.Path(old).read_bytes();ctx=self.runsql('context','MIGRATE '+quoted(old)).stdout.decode().strip();self.assertEqual((pathlib.Path(ctx)/'.legacy-state').read_bytes(),original);self.assertEqual((pathlib.Path(ctx)/'tables/0/a/title').read_bytes(),b'legacy exact pending');self.tx(ctx,'commit');self.assertEqual(self.select('title'),[['legacy exact pending']])
 def test_workspace_legacy_migration_collision_no_overwrite(self):
  old=self.legacy_context();self.provision();before=pathlib.Path(old).read_bytes();self.runsql('context','MIGRATE '+quoted(old),ok=4);self.assertEqual(pathlib.Path(old).read_bytes(),before)


 def test_workspace_torn_slot_retains_local_commit_decision(self):
  self.create();ctx=self.provision();self.runsql('insert',"RECORD a (title,age) VALUES ('durable local',1)",ok=93,env=dict(os.environ,SQL_CONTEXT=ctx,SQL_TEST_CRASH='journal-after-proof-remove'));p=pathlib.Path(ctx)/'.state';data=bytearray(p.read_bytes());slot=(len(data)-4096)//2;seq=[int.from_bytes(data[4096+i*slot:4104+i*slot],'little') for i in range(2)];latest=max(range(2),key=lambda i:seq[i]);data[4096+latest*slot+24]^=0x40;p.write_bytes(data);self.runsql('context','RESUME '+quoted(ctx));self.assertEqual(self.inspect_context(ctx)['phase'],4);self.assertEqual(self.select('title'),[['durable local']])
 def test_workspace_malformed_command_proof_refuses_recovery(self):
  self.create();ctx=self.provision();self.runsql('insert',"RECORD a (title,age) VALUES ('decided',1)",ok=86,env=dict(os.environ,SQL_CONTEXT=ctx,SQL_TEST_CRASH='after-decision'));p=pathlib.Path(ctx)/'.command-local';data=bytearray(p.read_bytes());data[-1]^=1;p.write_bytes(data);self.runsql('context','RESUME '+quoted(ctx),ok=4);self.assertTrue(list(self.table.glob('.sql-txn.*')));self.assertTrue(pathlib.Path(ctx).is_dir())
 def test_workspace_owned_input_integrity_checked_before_commit(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');source=self.base/'source';source.write_bytes(b'complete');self.tx(ctx,'insert',f'ADD TO blob VALUES (FILE({quoted(source)})) ALL RECORDS');captured=next((pathlib.Path(ctx)/'inputs').glob('*/*'));captured.write_bytes(b'badbytes');self.tx(ctx,'commit',ok=4);self.assertFalse((self.table/'a'/'blob').exists());self.assertTrue((pathlib.Path(ctx)/'tables/0/a/blob').exists());self.runsql('context','RESUME '+quoted(ctx),ok=4)
 def test_workspace_legacy_pending_local_journal_not_discarded(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title = 'legacy journal bytes' ALL RECORDS",ok=86,env={'SQL_TEST_CRASH':'after-decision'});old=self.base/('.context_'+str(os.getpid()));self.workspace_fixture('legacy',ctx,old);shutil.rmtree(ctx);ctx=self.runsql('context','MIGRATE '+quoted(old)).stdout.decode().strip();stage=pathlib.Path(ctx)/'tables/0';self.assertTrue(list(stage.glob('.sql-txn.*')));self.runsql('recover','TABLE ALL APPLY',cwd=stage);self.tx(ctx,'commit');self.assertEqual(self.select('title'),[['legacy journal bytes']])


 def test_workspace_staged_command_ack_crash_preserves_full_new_bytes(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');source=self.base/'source';data=bytes(range(256));source.write_bytes(data);self.tx(ctx,'insert',f'ADD TO blob VALUES (FILE({quoted(source)})) ALL RECORDS',ok=99,env={'SQL_TEST_CRASH':'command-before-ack'});source.unlink();self.runsql('context','RESUME '+quoted(ctx));self.assertEqual(self.inspect_context(ctx)['phase'],4);self.tx(ctx,'commit');self.assertEqual(self.runsql('select','blob OUTPUT RAW').stdout,data)
 def test_workspace_autocommit_ack_crash_resumes_without_reinsertion(self):
  self.create();ctx=self.provision();self.runsql('insert',"RECORD a (title,age) VALUES ('acked exactly once locally',1)",ok=99,env=dict(os.environ,SQL_CONTEXT=ctx,SQL_TEST_CRASH='command-before-ack'));self.runsql('context','RESUME '+quoted(ctx));self.assertEqual(self.inspect_context(ctx)['phase'],4);self.assertEqual(self.select('age'),[[1]])


 def test_workspace_effective_execution_options_are_in_command(self):
  self.create();ctx=self.provision();p=subprocess.run([str(SQL),'select','--context',ctx,'--lock-timeout','1234','title'],cwd=self.table,capture_output=True);self.assertEqual(p.returncode,0,p.stderr);frame=self.inspect_context(ctx);self.assertEqual(frame['lock_timeout'],1234);self.assertEqual(frame['output'],0);dump=self.ctxtool(ctx);self.assertIn(b'C.Command.LockTimeout',dump.stdout);p=subprocess.run(['/bin/sh','-eu'],input=dump.stdout,cwd=self.table,capture_output=True);self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.inspect_context(ctx)['lock_timeout'],1234)


 def test_workspace_cross_device_adoption_refused_before_decision(self):
  self.create();self.insert('a')
  with tempfile.TemporaryDirectory(prefix='sql-unit-adoption-',dir='/dev/shm') as tmp:
   source=pathlib.Path(tmp)/'bytes';source.write_bytes(b'different filesystem');self.assertNotEqual(source.stat().st_dev,self.table.stat().st_dev);self.workspace_fixture('crossdevice',str(self.table),source);self.assertEqual(source.read_bytes(),b'different filesystem');self.assertEqual(self.select('title'),[['hello']]);self.assertFalse(list(self.table.glob('.sql-txn.*')))


 def test_workspace_old_global_outcome_does_not_hide_new_local_decision(self):
  self.create();self.insert('a');ctx=self.provision();self.tx(ctx,'begin');self.tx(ctx,'update',"SET title='global complete' ALL RECORDS");self.tx(ctx,'commit');self.tx(ctx,'insert',"RECORD b (title,age) VALUES ('later local',2)",ok=86,env={'SQL_TEST_CRASH':'after-decision'});self.runsql('context','RESUME '+quoted(ctx));self.assertEqual(self.select('title ORDER BY age'),[['later local'],['global complete']]);self.assertFalse(list(self.table.glob('.sql-txn.*')))


 def test_workspace_long_original_cwd_command_mem_replay(self):
  self.create();ctx=self.provision();cwd=self.base/'long';cwd.mkdir()
  for i in range(17):cwd=cwd/('directory-'+str(i)+'-'+'x'*24);cwd.mkdir()
  self.assertGreater(len(str(cwd)),512);self.tx(ctx,'context','SET TRACE = 0',cwd=cwd);self.assertEqual(self.inspect_context(ctx)['cwd'],str(cwd));dump=self.ctxtool(ctx);p=subprocess.run(['/bin/sh','-eu'],input=dump.stdout,cwd=self.table,capture_output=True);self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.inspect_context(ctx)['cwd'],str(cwd))


 def test_journal_install_temporaries_preserve_unmanaged_record_files(self):
  self.create('(asset DIRECTORY RECORD (title TEXT))',' UNMATCHED IGNORE LINKS INTERNAL');self.runsql('insert',"RECORD a (title) VALUES ('source')");self.runsql('insert',"RECORD b (title) VALUES ('other')");files=[]
  for record in ('a','b'):
   for i in range(33):
    p=self.table/record/('.sql-apply.'+str(i));p.write_bytes(b'private original unmanaged');files.append(p)
  self.runsql('link',f"FIELD title TO 'a/title' FROM SOURCE {quoted(self.table)} WHERE record='b'");self.runsql('unlink',"FIELD title WHERE record='b'");self.runsql('update',"SET title='private' WHERE record='b'")
  for p in files:self.assertEqual(p.read_bytes(),b'private original unmanaged')
  self.assertEqual(self.select('title ORDER BY record'),[['source'],['private']])

if __name__=='__main__':unittest.main(verbosity=2)
