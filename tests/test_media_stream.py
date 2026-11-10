#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""STRICT structural JPG/MP4 validators and streamed (>64 MiB) payloads.
/tmp scratch fixtures only."""
import hashlib,json,os,pathlib,resource,struct,subprocess,tempfile,unittest
UNIT=pathlib.Path(__file__).resolve().parents[1];SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE',str(UNIT/'sql')))
def q(s):return "'"+str(s).replace("'","''")+"'"
BIG=70*1024*1024
def jpeg(entropy=b'\x12\xff\x00\x34\xff\xd0\x56',tail=b'',sof=True,sos=True):
 b=b'\xff\xd8'+b'\xff\xe0'+struct.pack('>H',16)+b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
 if sof:b+=b'\xff\xc0'+struct.pack('>H',11)+b'\x08\x00\x01\x00\x01\x01\x01\x11\x00'
 b+=b'\xff\xc4'+struct.pack('>H',4)+b'\x00\x00'
 if sos:b+=b'\xff\xda'+struct.pack('>H',8)+b'\x01\x01\x00\x00\x3f\x00'+entropy
 return b+b'\xff\xd9'+tail
def box(t,payload=b'',large=False,toend=False):
 if large:return struct.pack('>I',1)+t+struct.pack('>Q',16+len(payload))+payload
 if toend:return struct.pack('>I',0)+t+payload
 return struct.pack('>I',8+len(payload))+t+payload
MP4=box(b'ftyp',b'isom\x00\x00\x02\x00')+box(b'moov',box(b'mvhd',b'\x00'*8))+box(b'mdat',b'xyz',large=True)
class Base(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-media-');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name);self.t=self.base/'t';self.t.mkdir()
  self.env={k:v for k,v in os.environ.items() if k not in('SQL_CONTEXT','DATABASE_DIR')};self.env['DATABASE_DIR']=str(self.base)
 def sql(self,verb,text='',status=0,ctx=None,raw=False):
  env=dict(self.env)
  if ctx:env['SQL_CONTEXT']=ctx
  p=subprocess.run([str(SQL),verb,text],cwd=self.t,env=env,capture_output=True,timeout=120);self.assertEqual(p.returncode,status,(verb,text[:200],p.returncode,p.stdout[:200],p.stderr))
  return p
 def file(self,name,data):f=self.base/name;f.write_bytes(data);return f
 def put(self,rec,field,data,status=0):return self.sql('insert',f"RECORD {rec} ({field}) VALUES (FILE({q(self.file(rec+'.in',data))}))",status=status)
class Strict(Base):
 def setUp(self):super().setUp();self.sql('create','TABLE (r DIRECTORY RECORD (img JPG [0-1] STRICT, vid MP4 [0-1] STRICT, loose JPG [0-1]))')
 def test_valid_structures_accepted(self):
  self.put('a','img',jpeg());self.put('b','vid',MP4);self.put('c','vid',box(b'ftyp',b'mp42')+box(b'moov')+box(b'mdat',b'tail',toend=True));self.sql('check','TABLE DEEP')
 def test_invalid_jpeg_structures_refused(self):
  for i,bad in enumerate([b'\xff\xd8x\xff\xd9',jpeg(sof=False),jpeg(sos=False),jpeg(tail=b'junk'),jpeg()[:30]+b'\xff\xd9',b'\xff\xd8\xff\xe0\x00\x01\xff\xd9',jpeg(entropy=b'\x12\xff\xc0')]):
   self.put(f'j{i}','img',bad,status=4);self.assertFalse((self.t/f'j{i}').exists())
 def test_invalid_mp4_structures_refused(self):
  for i,bad in enumerate([box(b'ftyp',b'isom'),box(b'moov')+box(b'ftyp'),MP4+b'\x00\x00',box(b'ftyp')+struct.pack('>I',99)+b'moov',box(b'ftyp')+box(b'mo\x01v')]):
   self.put(f'm{i}','vid',bad,status=4)
 def test_non_strict_keeps_signature_check(self):
  self.put('a','loose',b'\xff\xd8x\xff\xd9');self.put('b','loose',b'nope',status=4)
 def test_alter_set_strict_validates_existing_and_drop(self):
  self.put('a','loose',b'\xff\xd8x\xff\xd9');self.sql('alter','TABLE ALTER FIELD loose SET STRICT',status=4)
  self.sql('delete',"WHERE record='a'");self.put('b','loose',jpeg());self.sql('alter','TABLE ALTER FIELD loose SET STRICT');self.put('c','loose',b'\xff\xd8x\xff\xd9',status=4)
  self.sql('alter','TABLE ALTER FIELD img DROP STRICT');self.put('d','img',b'\xff\xd8x\xff\xd9')
 def test_check_deep_detects_external_corruption(self):
  self.put('a','img',jpeg());(self.t/'a'/'img.jpg').write_bytes(jpeg(sof=False));self.sql('check','TABLE DEEP',status=4)
class Streaming(Base):
 def setUp(self):
  super().setUp();self.sql('create','TABLE (r DIRECTORY RECORD (blob OCTETS [0-1], img JPG [0-1] STRICT, txt TEXT [0-1]))')
  self.big=self.base/'big.bin'
  with open(self.big,'wb') as f:
   chunk=hashlib.sha256(b'seed').digest()*4096
   while f.tell()<BIG:f.write(chunk)
  self.digest=self.sha(self.big)
 def sha(self,path):
  h=hashlib.sha256()
  with open(path,'rb') as f:
   for c in iter(lambda:f.read(1<<20),b''):h.update(c)
  return h.hexdigest()
 def rss_kib(self,fn):
  before=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss;r=fn();after=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
  return r,after
 def test_insert_and_raw_select_stream_in_bounded_memory(self):
  _,rss=self.rss_kib(lambda:self.sql('insert',f"RECORD a (blob) VALUES (FILE({q(self.big)}))"))
  self.assertLess(rss,48*1024,'child peak RSS (KiB) must stay far below the 70 MiB payload');self.assertEqual(self.sha(self.t/'a'/'blob'),self.digest)
  out=self.sql('select',"CONTENT(blob) WHERE record='a' OUTPUT RAW").stdout;self.assertEqual(len(out),BIG);self.assertEqual(hashlib.sha256(out).hexdigest(),self.digest)
  self.sql('select',"blob WHERE record='a'",status=4);self.sql('check','TABLE DEEP')
 def test_update_and_add_with_streamed_file(self):
  self.sql('insert',"RECORD a (blob) VALUES ('small')");self.sql('update',f"SET blob = FILE({q(self.big)}) WHERE record='a'")
  self.assertEqual((self.t/'a'/'blob').stat().st_size,BIG)
 def test_streamed_strict_jpeg_and_utf8(self):
  j=self.base/'big.jpg';head=jpeg()[:-2]
  with open(j,'wb') as f:
   f.write(head);f.write(b'\x11'*(BIG));f.write(b'\xff\xd9')
  self.sql('insert',f"RECORD a (img) VALUES (FILE({q(j)}))");self.sql('check','TABLE DEEP')
  with open(j,'r+b') as f:f.seek(len(head)+BIG//2);f.write(b'\xff\xd8')
  self.sql('insert',f"RECORD b (img) VALUES (FILE({q(j)}))",status=4)
  t=self.base/'big.txt';unit='é€😀'.encode()
  with open(t,'wb') as f:
   f.write(unit*(BIG//len(unit)+1))
  self.sql('insert',f"RECORD c (txt) VALUES (FILE({q(t)}))")
  with open(t,'ab') as f:f.write(b'\xe2\x82')
  self.sql('insert',f"RECORD d (txt) VALUES (FILE({q(t)}))",status=4)
 def test_returning_with_streamed_value_refused_before_commit(self):
  self.sql('insert',f"RECORD a (blob) VALUES (FILE({q(self.big)})) RETURNING record",status=7);self.assertFalse((self.t/'a').exists())
 def test_streamed_value_in_transaction(self):
  c=self.sql('context',f'CREATE ON {q(self.base)} OWNER {os.getpid()}').stdout.decode().strip()
  self.sql('begin','READ WRITE',ctx=c);self.sql('insert',f"RECORD a (blob) VALUES (FILE({q(self.big)}))",ctx=c);self.assertFalse((self.t/'a').exists())
  self.big.unlink();self.sql('commit','',ctx=c);self.assertEqual(self.sha(self.t/'a'/'blob'),self.digest)
if __name__=='__main__':unittest.main()
