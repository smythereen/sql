/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Pointer/lifetime assertions against the actual mapping functions and sys ABI.
 */
#include "sql_local.h"
#include <assert.h>
static void config(const char *tool, const char *path, const char *value) {
  pid_t p = fork();
  assert(p >= 0);
  if (!p) {
    execl(tool, tool, path, "C.TraceLevel", value, (char *)NULL);
    _exit(127);
  }
  int status;
  assert(waitpid(p, &status, 0) == p);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
int main(int argc, char **argv) {
  assert(argc == 8);
  u32 caller = 0x55aa00u;
  TraceLevel = 0x123456u;
  TracePointer = &caller;
  u32 *saved = TracePointer;
  SQL_Result result = {0};
  Env e = {.out = &result};
  snprintf(e.cwd, sizeof(e.cwd), "%s", argv[1]);
  e.opt.context = argv[2];
  Table first = {.fd = -1}, nested = {.fd = -1};
  assert(!SQLi_table_open(&e, &first, argv[1], 0));
  assert(e.session);
  u32 *context = e.session->trace.word, *table = first.trace.word;
  assert(TracePointer == table && table != &first.map.TraceLevel &&
         context != &e.session->map.TraceLevel);
  assert(TraceLevel == 0x123456u);
  struct stat before, after;
  assert(!fstatat(first.fd, ".table", &before, AT_SYMLINK_NOFOLLOW));
  config(argv[3], argv[1], "16777216");
  assert(TracePointer == table && *table == SQL_TRACE &&
         Is_Trace_Level(SQL_TRACE));
  assert(!fstatat(first.fd, ".table", &after, AT_SYMLINK_NOFOLLOW) &&
         before.st_ino == after.st_ino);
  SQL_Map header;
  assert(!SQLi_map_read(&e, first.fd, ".table", &header));
  assert(TracePointer == table && *table == SQL_TRACE);
  assert(!sql_ctx_save(&e, e.session));
  assert(TracePointer == table);
  config(argv[4], argv[2], "16777216");
  assert(*context == SQL_TRACE && TracePointer == table);
  assert(!SQLi_table_open(&e, &nested, argv[5], 0));
  assert(TracePointer == nested.trace.word && TracePointer != table);
  SQLi_table_close(&nested);
  assert(TracePointer == table);
  config(argv[3], argv[1], "0");
  assert(!Is_Trace_Level(SQL_TRACE));
  SQLi_table_close(&first);
  assert(TracePointer == context && Is_Trace_Level(SQL_TRACE));
  Table view = {.fd = -1};
  assert(!sql_relation_open(&e, &view, argv[6]));
  assert(TracePointer == view.trace.word && TracePointer != context);
  config(argv[7], argv[6], "16777216");
  assert(Is_Trace_Level(SQL_TRACE));
  SQLi_table_close(&view);
  assert(TracePointer == context);
  sql_session_close(&e);
  assert(TracePointer == saved && TraceLevel == 0x123456u);
  SQL_Options options = {.cwd = argv[1], .context = argv[2]};
  assert(SQL_Select("missing", &options, &result) == SQL_SYNTAX);
  SQL_Free(&result);
  assert(TracePointer == saved && TraceLevel == 0x123456u);
  assert(SQL_Select("title", &options, &result) == SQL_OK);
  SQL_Free(&result);
  assert(TracePointer == saved && TraceLevel == 0x123456u);
  SQL_Binding binding = {"scope", SQL_BIND_TEXT, argv[6], strlen(argv[6])};
  options.bindings = &binding;
  options.binding_count = 1;
  assert(SQL_Select("* FROM :scope", &options, &result) == SQL_OK);
  SQL_Free(&result);
  assert(TracePointer == saved && TraceLevel == 0x123456u);
  assert(SQL_Select("not_exposed FROM :scope", &options, &result) ==
         SQL_SYNTAX);
  SQL_Free(&result);
  assert(TracePointer == saved && TraceLevel == 0x123456u);
  extern pid_t The_Line[32], New_Line[32];
  for (int i = 0; i < 32; i++) {
    The_Line[i] = 1000 + i;
    New_Line[i] = 2000 + i;
  }
  char root[PATH_MAX];
  snprintf(root, sizeof(root), "%s", argv[2]);
  char *slash = strstr(root, "/.context/");
  assert(slash);
  *slash = 0;
  SQL_Options inherited = {.cwd = root};
  assert(SQL_Context("SHOW", &inherited, &result) == SQL_OK);
  SQL_Free(&result);
  for (int i = 0; i < 32; i++) {
    assert(The_Line[i] == 1000 + i);
    assert(New_Line[i] == 2000 + i);
  }
  assert(TracePointer == saved && TraceLevel == 0x123456u);
  puts("TRACE_SCOPE_OK");
  return 0;
}
