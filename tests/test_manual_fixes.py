#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright (c) 2026 John R. Smythe Jr.
"""Regressions for defects found while writing/verifying MANUAL.md (2026-11-09)."""
import os, shutil, subprocess, tempfile, unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.environ.get('SQL_TEST_EXECUTABLE', os.path.join(HERE, 'sql'))


class ManualFixes(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='sql-manualfix-')

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def sql(self, *args, cwd=None, ok=True):
        r = subprocess.run([EXE, *args], cwd=cwd or self.d, capture_output=True, text=True)
        if ok:
            self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def test_member_update_skips_records_without_members(self):
        self.sql('create', "TABLE 't' (r DIRECTORY RECORD (title TEXT, tags TEXT [0-]))")
        t = os.path.join(self.d, 't')
        self.sql('insert', "RECORD 'a' (title, tags, tags) VALUES ('A', 'x', 'y')", cwd=t)
        self.sql('insert', "RECORD 'b' (title) VALUES ('B')", cwd=t)
        self.sql('update', "SET tags = 'X' WHERE CONTENT(tags) = 'x' ALL MEMBERS", cwd=t)
        r = self.sql('select', "record, tags ORDER BY record", cwd=t)
        self.assertEqual(r.stdout, '[["a",["X","y"]],["b",[]]]\n')
        # scalar UPDATE of an absent optional member is still refused
        self.sql('alter', "TABLE ADD FIELD note TEXT [0-1]", cwd=t)
        r = self.sql('update', "SET note = 'n' WHERE title = 'B'", cwd=t, ok=False)
        self.assertEqual(r.returncode, 4)
        self.assertIn('INSERT ADD TO is required', r.stderr)

    def test_show_views_lists_branch_roots(self):
        self.sql('create', "TABLE 'p' (r DIRECTORY RECORD (name TEXT, age INT64))")
        self.sql('insert', "INTO 'p' RECORD 'a' (name, age) VALUES ('A', 1)")
        self.sql('create', "VIEW 'saved' AS SELECT name FROM 'p'")
        self.sql('create', "VIEW 'multi' LINKED BRANCHES (one AS SELECT name FROM 'p' ; two AS SELECT name FROM 'p' WHERE age > 5)")
        r = self.sql('show', "VIEWS IN '.'")
        self.assertEqual(sorted(r.stdout.split()), ['"multi"', '"saved"'])

    def test_autocommit_workspace_serves_as_context(self):
        script = (f'set -e; cd {self.d}; S={EXE}; '
                  '$S create "TABLE \'t\' (r DIRECTORY RECORD (v TEXT))"; '
                  'if $S context "CREATE ON \'.\'" 2>err; then exit 9; fi; '
                  'grep -q "PID workspace collision" err; '
                  '$S begin ""; $S insert "INTO \'t\' RECORD \'x\' (v) VALUES (\'1\')"; '
                  'test "$($S select "v FROM \'t\' OUTPUT LINES")" = 1; '
                  '$S rollback ""; test "$($S select "v FROM \'t\'")" = "[]"; '
                  '$S begin ""; $S insert "INTO \'t\' RECORD \'x\' (v) VALUES (\'2\')"; $S commit ""; '
                  '$S select "v FROM \'t\' OUTPUT LINES"')
        r = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stdout, '2\n')

    def test_top_level_unmatched_entry_has_no_leading_slash(self):
        os.mkdir(os.path.join(self.d, 'n'))
        open(os.path.join(self.d, 'n', 'file'), 'w').close()
        r = self.sql('define', "TABLE 'n' (x DIRECTORY RECORD MATCH 'r[0-9]+' (v TEXT)) VALIDATE ONLY", ok=False)
        self.assertEqual(r.returncode, 4)
        self.assertIn('unmatched filesystem entry file', r.stderr)
        self.assertNotIn('entry /file', r.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
