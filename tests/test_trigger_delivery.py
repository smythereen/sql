#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Bounded trigger-only integration checks; all handlers/data are local scratch."""
import json, os, pathlib, subprocess, tempfile, time, unittest
UNIT=pathlib.Path(__file__).resolve().parents[1]
SQL=pathlib.Path(os.environ.get('SQL_TEST_EXECUTABLE', str(UNIT/'sql')))
def q(s): return "'"+str(s).replace("'", "''")+"'"
class TriggerDelivery(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sql-trigger-delivery-'); self.addCleanup(self.tmp.cleanup)
  self.base=pathlib.Path(self.tmp.name); self.table=self.base/'table'; self.table.mkdir()
  self.log=self.base/'log'; self.control=self.base/'control'; self.control.write_text('ok')
  self.handler=self.base/'handler'; self.handler.write_text(r"""#!/usr/bin/python3
import json, os, pathlib, sys, time
e=json.load(sys.stdin); log=pathlib.Path(sys.argv[1]); mode=pathlib.Path(sys.argv[2]).read_text()
with log.open('a') as f:
 f.write(json.dumps({'event':e,'pid':os.getpid(),'args':sys.argv[3:]})+'\n'); f.flush(); os.fsync(f.fileno())
if mode=='sleep': time.sleep(3)
if mode=='fail' or (mode=='retry' and len(log.read_text().splitlines())==1): sys.exit(23)
"""); self.handler.chmod(0o700)
  self.call('create','TABLE (asset DIRECTORY RECORD (title TEXT, age INT64 [0-1])) LINKS INTERNAL')
 def tearDown(self):
  for row in self.rows(): self.assertFalse(pathlib.Path('/proc',str(row['pid'])).exists(),'scratch handler remains after watcher exit')
 def call(self,verb,text='',status=0,env=None):
  config=dict(os.environ);config.pop('SQL_CONTEXT',None)
  if env: config.update(env)
  p=subprocess.run([str(SQL),verb,text],cwd=self.table,env=config,capture_output=True,timeout=8)
  self.assertEqual(p.returncode,status,(verb,text,p.returncode,p.stdout,p.stderr));return p
 def register(self,name='notify',after='COMMIT',enabled=True,tail=''):
  self.call('trigger',f'CREATE {name} AFTER {after} EXECUTE {q(self.handler)} ARGUMENTS ({q(self.log)},{q(self.control)},'+q("literal $(not-a-command); 'quoted'")+f') {tail} '+('ENABLED' if enabled else 'DISABLED'))
 def insert(self,name='a'): self.call('insert',f"RECORD {name} (title) VALUES ('first')")
 def watch(self,name='ALL',**kw): return json.loads(self.call('watch',f'FOR {name} ONCE',**kw).stdout)
 def rows(self): return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
 def state(self): return json.loads(self.call('trigger','SHOW').stdout)[0]
 def test_committed_insert_update_delete_payload_and_restart(self):
  self.register();self.insert();self.call('update',"SET title='second' ALL RECORDS");self.call('delete',"WHERE record='a'")
  self.assertEqual(self.watch()['delivered'],3);rows=self.rows();self.assertEqual(len(rows),3)
  self.assertEqual([r['event']['logical'][0]['kind'] for r in rows],[1,2,4])
  for r in rows:
   e=r['event'];self.assertEqual(e['table'],str(self.table));self.assertEqual(len(e['transaction']),32)
   self.assertEqual(e['logical'][0]['record'],'a');self.assertEqual(e['logical'][0]['field'],'title');self.assertEqual(e['logical'][0]['path'],'a/title')
   self.assertEqual(r['args'],["literal $(not-a-command); 'quoted'"])
  self.assertEqual(len({r['event']['transaction'] for r in rows}),3)
  before=self.state();self.assertEqual(before['delivered'],3);self.assertEqual(self.watch()['delivered'],0);self.assertEqual(self.state(),before);self.assertEqual(len(self.rows()),3)
 def test_disabled_kind_and_field_filters_checkpoint_skips(self):
  self.register(after='UPDATE OF (title)',enabled=False);self.insert();initial=self.state()['checkpoint']
  self.assertEqual(self.watch()['delivered'],0);self.assertEqual(self.rows(),[]);self.assertEqual(self.state()['checkpoint'],initial)
  self.call('trigger','ENABLE notify');self.assertEqual(self.watch()['skipped'],1)
  self.call('insert','ADD TO age VALUES (4) ALL RECORDS');self.assertEqual(self.watch()['skipped'],1)
  self.call('update','SET age=5 ALL RECORDS');self.assertEqual(self.watch()['skipped'],1)
  self.call('update',"SET title='match' ALL RECORDS");self.assertEqual(self.watch()['delivered'],1)
  self.assertEqual(len(self.rows()),1);self.assertEqual(self.state()['delivered'],1);self.assertEqual(self.watch()['delivered'],0)
 def test_rollback_no_delivery_explicit_commit_only(self):
  self.insert();self.register();ctx=self.call('context','CREATE ON '+q(self.base)).stdout.decode().strip();env={'SQL_CONTEXT':ctx}
  before=set((self.table/'.sql/events').iterdir());self.call('begin',env=env);self.call('update',"SET title='rolled back' ALL RECORDS",env=env)
  self.assertEqual(self.watch()['delivered'],0);self.call('rollback',env=env);self.assertEqual(set((self.table/'.sql/events').iterdir()),before)
  self.call('begin',env=env);self.call('update',"SET title='committed' ALL RECORDS",env=env);self.assertEqual(self.watch()['delivered'],0);self.call('commit',env=env)
  self.assertEqual(self.watch()['delivered'],1);self.assertEqual(len(self.rows()),1)
 def test_failure_bounded_retries_stable_id_then_success(self):
  self.register(tail='RETRIES 2');self.insert();initial=self.state()['checkpoint'];self.control.write_text('fail')
  self.call('watch','FOR ALL ONCE',status=3);rows=self.rows();self.assertEqual(len(rows),3);self.assertEqual(len({r['event']['transaction'] for r in rows}),1)
  self.assertEqual(self.state()['checkpoint'],initial);self.assertEqual(self.state()['status'],23)
  self.control.write_text('ok');self.assertEqual(self.watch()['delivered'],1);self.assertEqual(self.rows()[-1]['event'],rows[0]['event']);self.assertEqual(self.watch()['delivered'],0)
 def test_retry_succeeds_on_second_attempt(self):
  self.register(tail='RETRIES 1');self.control.write_text('retry');self.insert();self.assertEqual(self.watch()['delivered'],1)
  self.assertEqual(len(self.rows()),2);self.assertEqual(self.rows()[0]['event'],self.rows()[1]['event']);self.assertEqual(self.state()['delivered'],1)
 def test_timeout_no_ack_child_reaped_then_retry(self):
  self.register(tail='TIMEOUT 120');self.insert();initial=self.state()['checkpoint'];self.control.write_text('sleep');start=time.monotonic()
  self.call('watch','FOR ALL ONCE',status=3);self.assertLess(time.monotonic()-start,2);self.assertEqual(self.state()['status'],124);self.assertEqual(self.state()['checkpoint'],initial)
  rows=self.rows();self.assertEqual(len(rows),1);self.assertFalse(pathlib.Path('/proc',str(rows[0]['pid'])).exists())
  self.control.write_text('ok');self.assertEqual(self.watch()['delivered'],1);self.assertEqual(self.rows()[-1]['event'],rows[0]['event'])
 def test_after_sideeffect_before_checkpoint_crash_at_least_once(self):
  self.register();self.insert();initial=self.state()['checkpoint'];self.call('watch','FOR ALL ONCE',status=110,env={'SQL_TEST_CRASH':'watch-after-exec'})
  self.assertEqual(len(self.rows()),1);self.assertEqual(self.state()['checkpoint'],initial);self.assertEqual(self.watch()['delivered'],1)
  self.assertEqual(len(self.rows()),2);self.assertEqual(self.rows()[0]['event'],self.rows()[1]['event']);self.assertEqual(self.watch()['delivered'],0)
 def test_kind_and_field_must_match_same_logical_event(self):
  self.insert();self.register(after='INSERT OF (title)');ctx=self.call('context','CREATE ON '+q(self.base)).stdout.decode().strip();env={'SQL_CONTEXT':ctx}
  self.call('begin',env=env);self.call('update',"SET title='update not insert' ALL RECORDS",env=env);self.call('insert','ADD TO age VALUES (7) ALL RECORDS',env=env);self.call('commit',env=env)
  self.assertEqual(self.watch()['delivered'],0);self.assertEqual(self.rows(),[])
  self.insert('b');self.assertEqual(self.watch()['delivered'],1)
 def test_filtered_event_escaped_record_path(self):
  name="odd'\"record";self.call('insert',f'RECORD {q(name)} (title) VALUES (\'before\')');self.register(after='UPDATE OF (title)')
  self.call('update',"SET title='after' ALL RECORDS");self.assertEqual(self.watch()['delivered'],1);self.assertEqual(self.rows()[0]['event']['logical'][0]['record'],name)
 def test_live_trigger_unit_wakeup_orderly_exit(self):
  self.register();p=subprocess.Popen([str(SQL),'watch','FOR ALL CONTINUOUS DURATION 1200'],cwd=self.table,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={k:v for k,v in os.environ.items() if k!='SQL_CONTEXT'})
  try:
   deadline=time.monotonic()+3;ready=False
   while time.monotonic()<deadline and p.poll() is None:
    for f in pathlib.Path('/proc',str(p.pid),'fdinfo').glob('*'):
     try: ready=ready or 'inotify wd:' in f.read_text()
     except FileNotFoundError: pass
    if ready: break
    time.sleep(.01)
   self.assertTrue(ready,'actual registered inotify watch not observed');self.insert();out,err=p.communicate(timeout=4)
   self.assertEqual(p.returncode,0,(out,err));result=json.loads(out);self.assertGreater(result['wakeups'],0);self.assertEqual(result['delivered'],1);self.assertEqual(len(self.rows()),1)
  finally:
   if p.poll() is None: p.kill();p.communicate()
 def test_decided_not_applied_gate_then_recovery_once(self):
  self.register();self.call('insert',"RECORD a (title) VALUES ('decided')",status=86,env={'SQL_TEST_CRASH':'after-decision'})
  self.call('watch','FOR ALL ONCE',status=6);self.assertEqual(self.rows(),[]);self.call('recover','TABLE ALL APPLY')
  self.assertEqual(self.watch()['delivered'],1);self.assertEqual(self.watch()['delivered'],0);self.assertEqual(len(self.rows()),1)
 def test_shared_anchor_fans_out_two_logical_records(self):
  self.insert('a');self.insert('b');self.call('link',"FIELD title TO 'a/title' FROM SOURCE . ALL RECORDS");self.register(after='UPDATE OF (title)')
  self.call('update',"SET title='shared' WHERE record='a'");self.assertEqual(self.watch()['delivered'],1)
  logical=self.rows()[0]['event']['logical'];self.assertEqual({r['record'] for r in logical},{'a','b'});self.assertTrue(all(r['kind']&2 for r in logical))
if __name__=='__main__': unittest.main(verbosity=2)
