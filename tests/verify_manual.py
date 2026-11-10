#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Run every ```console example in MANUAL.md in order and compare output.

Usage: verify_manual.py [--record]   (SQL_TEST_EXECUTABLE selects the binary;
default ./sql in the unit directory).  Scratch root: /tmp/sql-demo (removed
and recreated).  '<...>' in an expected line matches any text.  A trailing
'[exit N]' line states a non-zero exit status.  stderr is merged into stdout.
"""
import os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANUAL = os.path.join(HERE, 'MANUAL.md')
ROOT = '/tmp/sql-demo'


def examples(text):
    out, block = [], None
    for number, line in enumerate(text.split('\n'), 1):
        if block is None:
            if line.strip() == '```console':
                block = []
            continue
        if line.strip() == '```':
            out.extend(block)
            block = None
            continue
        if line.startswith('$ '):
            block.append({'cmd': line[2:], 'line': number, 'expect': []})
        elif block:
            block[-1]['expect'].append(line)
    return out


def pattern(line):
    parts = line.split('<...>')
    return re.compile('^' + '.*?'.join(re.escape(p) for p in parts) + '$')


def main():
    record = '--record' in sys.argv
    exe = os.environ.get('SQL_TEST_EXECUTABLE', os.path.join(HERE, 'sql'))
    cmds = examples(open(MANUAL).read())
    bindir = tempfile.mkdtemp(prefix='sql-manual-bin-')
    os.symlink(os.path.abspath(exe), os.path.join(bindir, 'sql'))
    shutil.rmtree(ROOT, ignore_errors=True)
    os.makedirs(ROOT)
    script = ['set +e', 'unset CDPATH SQL_CONTEXT DATABASE_DIR', 'export LC_ALL=C',
              f'export PATH={bindir}:/usr/bin:/bin', f'cd {ROOT}']
    for i, c in enumerate(cmds):
        script.append(f"printf '\\n@@B{i}@@\\n'")
        script.append('{ ' + c['cmd'] + ' ; } 2>&1')
        script.append(f"printf '\\n@@E{i} %d@@\\n' $?")
    r = subprocess.run(['bash', '-c', '\n'.join(script)], capture_output=True)
    shutil.rmtree(bindir, ignore_errors=True)
    data = r.stdout.decode('utf-8', 'replace')
    failures = 0
    for i, c in enumerate(cmds):
        m = re.search(rf'\n@@B{i}@@\n(.*?)\n@@E{i} (\d+)@@\n', data, re.S)
        if not m:
            print(f'MANUAL.md:{c["line"]}: no output captured for: {c["cmd"]}')
            failures += 1
            continue
        got = [l for l in m.group(1).split('\n')]
        while got and got[-1] == '':
            got.pop()
        if m.group(2) != '0':
            got.append(f'[exit {m.group(2)}]')
        exp = list(c['expect'])
        while exp and exp[-1] == '':
            exp.pop()
        ok = len(got) == len(exp) and all(pattern(e).match(g) for e, g in zip(exp, got))
        if record or not ok:
            print(f'--- MANUAL.md:{c["line"]}: $ {c["cmd"]}' + ('' if ok else '   [MISMATCH]'))
            if not ok:
                print('  expected:'); [print('    ' + e) for e in exp]
            print('  actual:'); [print('    ' + g) for g in got]
        failures += not ok
    print(f'{len(cmds)} manual commands, {len(cmds) - failures} matched, {failures} mismatched')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
