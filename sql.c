/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql.h"
#include <stdio.h>
#include <string.h>
extern int sql_ctxmem_entry(int, char **);
extern int sql_viewmem_cli(int, char **);
extern int sql_trgmem_cli(int, char **);
/* far.c-style command table, with exact rather than ambiguous-prefix matching.
 */
static const char *commands[] = {
    "create",     "define",  "describe", "show",    "select",  "insert",
    "update",     "delete",  "link",     "unlink",  "alter",   "drop",
    "begin",      "commit",  "rollback", "context", "trigger", "watch",
    "check",      "recover", "tblmem",   "ctxmem",  "viewmem", "trgmem",
    "triggermem", NULL};
int main(int ac, char **av) {
  const char *base = strrchr(av[0], '/');
  base = base ? base + 1 : av[0];
  const char *command = NULL;
  if (!strncmp(base, "sql_", 4))
    command = base + 4;
  else if (ac >= 2) {
    command = av[1];
    av++;
    ac--;
  }
  if (!command || !strcmp(command, "--help")) {
    fputs("sql command [SQL clauses]\nCommands:", stderr);
    for (int i = 0; commands[i]; i++)
      fprintf(stderr, " %s", commands[i]);
    fputc('\n', stderr);
    return command ? 0 : 2;
  }
  if (!strcmp(command, "viewmem"))
    return sql_viewmem_cli(ac, av);
  if (!strcmp(command, "ctxmem") || !strcmp(command, "contextmem"))
    return sql_ctxmem_entry(ac, av);
  if (!strcmp(command, "trgmem") || !strcmp(command, "triggermem"))
    return sql_trgmem_cli(ac, av);
  if (!strcmp(command, "tblmem"))
    return SQL_MemCLI(command, ac, av);
  return SQL_CLI(command, ac, av);
}
