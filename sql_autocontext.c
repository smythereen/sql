/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Valid initializer for command workspaces, not zero-map auto-use. Reads do
 * not provision; writes retain exact commands and actual redo until applied. */
#include "sql_local.h"
int sql_autocontext(Env *e, Parser *p) {
  if (e->session || e->no_context || !e->verb)
    return 0;
  const char *verbs[] = {"create", "define",  "insert", "update",
                         "delete", "link",    "unlink", "alter",
                         "drop",   "trigger", "watch",  NULL};
  int write = 0;
  for (int i = 0; verbs[i]; i++)
    if (!strcmp(e->verb, verbs[i]))
      write = 1;
  if (!write)
    return 0;
  for (int i = 0; i + 1 < p->n; i++)
    if (!p->t[i].quoted && !strcasecmp(p->t[i].s, "VALIDATE") &&
        !strcasecmp(p->t[i + 1].s, "ONLY"))
      return 0;
  if (!strcmp(e->verb, "trigger") && p->n && !strcasecmp(p->t[0].s, "SHOW"))
    return 0;
  Parser *init = calloc(1, sizeof(*init));
  if (!init)
    return SQLi_fail(e, SQL_IO, "autocommit constructor allocation");
  init->t[0] = (Tok){"ON", 0};
  init->t[1] = (Tok){e->cwd, 1};
  init->n = 2;
  char owner[32], handle[PATH_MAX];
  int watching = !strcmp(e->verb, "watch");
  if (watching) {
    if (e->opt.context)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "WATCH uses its own process workspace, not an explicit "
                       "shared context");
    snprintf(owner, sizeof(owner), "%ld", (long)getpid());
    init->t[2] = (Tok){"OWNER", 0};
    init->t[3] = (Tok){owner, 0};
    init->n = 4;
  }
  e->provisioning = 1;
  int rc = sql_context_create(e, init);
  e->provisioning = 0;
  free(init);
  if (rc)
    return -1;
  if (watching) {
    char rel[80];
    snprintf(rel, sizeof(rel), ".context/%ld", (long)getpid());
    if (SQLi_joinpath(e, handle, e->cwd, rel))
      return -1;
    return sql_session_load(e, handle, NULL, 1);
  }
  return sql_session_load(e, NULL, NULL, 1);
}

int sql_provisioned_metadata(Env *e, int fd, const char *name) {
  if (!e->session || (strcmp(name, ".context") && strcmp(name, ".sql-root")))
    return 0;
  struct stat a, b;
  return !fstat(fd, &a) && !fstat(e->session->root, &b) &&
         a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
