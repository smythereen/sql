#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Installed binary/API parity, using only a newly owned scratch database."""
import json,os,pathlib,subprocess,tempfile
unit=pathlib.Path(__file__).resolve().parents[1];home=unit.parent;bin=home/'bin';sql=bin/'sql';env=os.environ.copy();env.pop('SQL_CONTEXT',None)
def quote(x):return "'"+str(x).replace("'","''")+"'"
def run(cmd,text='',cwd=None,context=None):
 p=subprocess.run([str(sql),cmd]+(['--context',context] if context else [])+[text],cwd=cwd or unit,capture_output=True,timeout=15,env=env);assert p.returncode==0,(cmd,text,p.returncode,p.stderr);return p.stdout
assert (unit/'sql').read_bytes()==sql.read_bytes();assert (unit/'sql.h').read_bytes()==(home/'cmn'/'sql.h').read_bytes()
commands='create define describe show select insert update delete link unlink alter drop begin commit rollback context trigger watch check recover tblmem ctxmem contextmem viewmem'.split()
for name in commands:assert (bin/('sql_'+name)).is_symlink() and (bin/('sql_'+name)).resolve()==sql.resolve()
members=subprocess.run(['ar','t',str(home/'lib'/'libsql.a')],capture_output=True,check=True).stdout.decode().splitlines();assert 'sql.o' not in members
for name in commands[:20]:assert 'sql_'+name+'.o' in members
with tempfile.TemporaryDirectory(prefix='sql-installed-check-') as scratch:
 root=pathlib.Path(scratch);table=root/'table';view=root/'view';run('create','TABLE '+quote(table)+' (r DIRECTORY RECORD (title TEXT))');run('insert',"RECORD a (title) VALUES ('installed')",table);run('create','VIEW '+quote(view)+' AS SELECT title AS label FROM '+quote(table));assert json.loads(run('select','label',view))==[['installed']]
 for name in ['c-client','cpp-client']:
  p=subprocess.run([str(unit/'examples'/name),str(view),'label'],capture_output=True,timeout=15,env=env);assert p.returncode==0,p.stderr;assert json.loads(p.stdout)==[['installed']]
 ctx=run('context','CREATE ON '+quote(root)+' OWNER '+str(os.getpid())).decode().strip()
 for name,value in [('c-transaction','C linked library'),('cpp-transaction','C++ linked library')]:
  p=subprocess.run([str(unit/'examples'/name),str(table),ctx,value],capture_output=True,timeout=15,env=env);assert p.returncode==0,p.stderr;assert json.loads(p.stdout)['outcome']=='committed';assert json.loads(run('select','label',view))==[[value]]
 assert json.loads(run('show','CONTEXTS ON '+quote(root)))['owner_live']
 run('context','CLOSE',context=ctx)
print('PASS: installed/source binary and header byte-equal; 24 aliases resolve to sql; 20 separate operation objects and no sql.o in libsql.a; installed view queries and SHOW CONTEXTS verified; four direct C/C++ select/transaction clients ran against installed libsql.a; all scratch only.')
