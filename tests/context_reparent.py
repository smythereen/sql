#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Owned scratch-process test: reparent a still-live context owner."""
import ctypes,json,os,pathlib,subprocess,sys,time
sql,root,table=sys.argv[1:];assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
r,w=os.pipe();ackr,ackw=os.pipe()
def run(cmd,text='',context=None):
 args=[sql,cmd]+(['--context',context] if context else [])+[text]
 return subprocess.run(args,cwd=root,capture_output=True,timeout=10)
def quote(x):return "'"+str(x).replace("'","''")+"'"
bridge=os.fork()
if not bridge:
 os.close(r);owner=os.fork()
 if owner:
  os.close(ackw);os.read(ackr,1);os._exit(0)
 os.close(ackr);oldparent=os.getppid();p=run('context','CREATE ON '+quote(root));assert p.returncode==0,p.stderr
 ctx=p.stdout.decode().strip();assert run('begin','',ctx).returncode==0
 assert run('update',quote(table)+" SET title='reparented' ALL RECORDS",ctx).returncode==0
 os.write(ackw,b'1');os.close(ackw)
 until=time.monotonic()+5
 while os.getppid()==oldparent and time.monotonic()<until:time.sleep(.005)
 assert os.getppid()!=oldparent
 implicit=run('context','SHOW');explicit=run('context','SHOW',ctx);clean=run('context','CLEAN STALE ON '+quote(root));kept=pathlib.Path(ctx).exists();resumed=run('context','RESUME '+quote(ctx));assert resumed.returncode==0,resumed.stderr;ctx=resumed.stdout.decode().strip();commit=run('commit','',ctx)
 os.write(w,json.dumps({'owner':os.getpid(),'context':ctx,'implicit':implicit.returncode,'diagnostic':implicit.stderr.decode(),'explicit':explicit.returncode,'clean':clean.returncode,'kept':kept,'commit':commit.returncode}).encode());os.close(w);os._exit(0)
os.close(w);os.close(ackr);os.close(ackw);_,status=os.waitpid(bridge,0);assert status==0
parts=[]
while True:
 b=os.read(r,65536)
 if not b:break
 parts.append(b)
result=json.loads(b''.join(parts));_,status=os.waitpid(result['owner'],0);assert status==0
print(json.dumps(result))
