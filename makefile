# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
include ../rules.mak
CHDRS = $(HDR)/sql.h
LIBRARIES = -ltrigger -lmio -lmap -lfar -lnow -lsem -lsys
SYS_LIBS = -lpthread
CFLAGS += -std=gnu11 -Wall -Wextra -Werror=implicit-function-declaration -I.
include ../targets.mak
COMMANDS = create define describe show select insert update delete link unlink alter drop begin commit rollback context trigger watch check recover
.PHONY: aliases test
all:: aliases
aliases: $(BIN)/sql
	@for c in $(COMMANDS) tblmem ctxmem contextmem viewmem trgmem triggermem; do test ! -e $(BIN)/sql_$$c || test -L $(BIN)/sql_$$c || { echo "refusing to replace non-link sql_$$c" >&2; exit 1; }; ln -sfn sql $(BIN)/sql_$$c || exit; done
$(BIN)/sql: sql
sql: $(LIBRARY)
TESTS = test_sql test_ddl test_cross_share test_ids_names test_media_stream \
	test_txn_reads test_trigger_delivery test_linked_views test_view_watch \
	test_multiview test_context_root_default test_events_more test_failure_matrix \
	test_manual_fixes
TEST_ENV = env -u SQL_CONTEXT -u DATABASE_DIR -u SQL_TEST_CRASH -u SQL_TEST_FAIL
test:: all examples
	@for t in $(TESTS); do echo "== $$t"; $(TEST_ENV) python3 tests/$$t.py || exit 1; done
	$(TEST_ENV) python3 tests/verify_manual.py
	$(TEST_ENV) python3 tests/verify_installed.py
	$(TEST_ENV) SQL_TEST_EXECUTABLE=$(HOME)/bin/sql python3 tests/verify_manual.py
-include .depend

.PHONY: examples sanitize
examples: examples/c-client examples/cpp-client examples/c-transaction examples/cpp-transaction
examples/c-client: examples/select.c $(LIBRARY) $(CHDRS)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LIBRARY) $(LIBRARIES) $(SYS_LIBS)
examples/cpp-client: examples/select.cc $(LIBRARY) $(CHDRS)
	$(CXX) $(CXXFLAGS) -std=c++11 $< -o $@ $(LDFLAGS) $(LIBRARY) $(LIBRARIES) $(SYS_LIBS)
examples/c-transaction: examples/transaction.c $(LIBRARY) $(CHDRS)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LIBRARY) $(LIBRARIES) $(SYS_LIBS)
examples/cpp-transaction: examples/transaction.cc examples/transaction.c $(LIBRARY) $(CHDRS)
	$(CXX) $(CXXFLAGS) -std=c++11 $< -o $@ $(LDFLAGS) $(LIBRARY) $(LIBRARIES) $(SYS_LIBS)
sanitize: all
	mkdir -p tests/sanitize
	$(CC) -g -O1 -no-pie -fno-omit-frame-pointer -fsanitize=address,undefined -I. -I$(HDR) -std=gnu11 -Wall -Wextra $(wildcard sql*.c) -o tests/sql-sanitize $(LDFLAGS) $(LIBRARIES) $(SYS_LIBS)
	ln -sfn ../sql-sanitize tests/sanitize/sql_tblmem
	$(CC) -g -O1 -no-pie -fno-omit-frame-pointer -fsanitize=address,undefined -I. -I$(HDR) -std=gnu11 -Wall -Wextra tests/trace_scope.c $(filter-out sql.c,$(wildcard sql*.c)) -o tests/trace-sanitize $(LDFLAGS) $(LIBRARIES) $(SYS_LIBS)
	ln -sfn ../sql-sanitize tests/sanitize/sql_viewmem
	ln -sfn ../sql-sanitize tests/sanitize/sql_ctxmem
	ln -sfn ../sql-sanitize tests/sanitize/sql_contextmem
	ln -sfn ../sql-sanitize tests/sanitize/sql_trgmem
	ln -sfn ../sql-sanitize tests/sanitize/sql_triggermem
	SQL_TEST_TRACE_EXECUTABLE="$(CURDIR)/tests/trace-sanitize" SQL_TEST_EXECUTABLE="$(CURDIR)/tests/sql-sanitize" SQL_TEST_MEM_EXECUTABLE="$(CURDIR)/tests/sanitize/sql_tblmem" SQL_TEST_CTXMEM_EXECUTABLE="$(CURDIR)/tests/sanitize/sql_ctxmem" SQL_TEST_VIEWMEM_EXECUTABLE="$(CURDIR)/tests/sanitize/sql_viewmem" SQL_TEST_TRGMEM_EXECUTABLE="$(CURDIR)/tests/sanitize/sql_trgmem" PATH="$(CURDIR)/tests/sanitize:$$PATH" ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 sh -c 'for t in $(TESTS); do echo "== $$t (sanitized)"; $(TEST_ENV) python3 tests/$$t.py || exit 1; done; echo "== verify_manual (sanitized)"; $(TEST_ENV) python3 tests/verify_manual.py'
