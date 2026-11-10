/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
int sql_admin_cmd(Env *e, const char *cmd, Parser *p) {
  if (!strcasecmp(cmd, "recover")) {
    int database = SQLi_eat(p, "DATABASE");
    if (!database && SQLi_need(e, p, "TABLE"))
      return -1;
    char *path = NULL, *id = NULL;
    if (!SQLi_is(p, "ALL") && !SQLi_is(p, "TRANSACTION"))
      path = take(e, p);
    if (SQLi_eat(p, "TRANSACTION")) {
      id = take(e, p);
      if (!id || strlen(id) != 32)
        return SQLi_fail(e, SQL_SYNTAX,
                         "transaction ID requires 32 hex digits");
      for (char *s = id; *s; s++)
        if (!isxdigit((unsigned char)*s))
          return SQLi_fail(e, SQL_SYNTAX, "invalid transaction ID");
    } else if (SQLi_need(e, p, "ALL"))
      return -1;
    int change = SQLi_eat(p, "APPLY");
    if (!change && SQLi_eat(p, "REPORT"))
      if (SQLi_need(e, p, "ONLY"))
        return -1;
    if (SQLi_end(e, p))
      return -1;
    if (sql_session_load(e, NULL, NULL, 0))
      return -1;
    if (database) {
      int fd = path         ? SQLi_open_dir(e, path)
               : e->session ? dup(e->session->root)
                            : SQLi_open_dir(e, NULL);
      if (fd < 0)
        return -1;
      int rc = sql_coord_recover(e, fd, path, change, id, NULL);
      close(fd);
      return rc;
    }
    if (id)
      return SQLi_fail(e, SQL_UNSUPPORTED,
                       "TABLE transaction selection is not yet supported; use "
                       "ALL or DATABASE TRANSACTION");
    Table t = {.fd = -1};
    t.fd = SQLi_open_dir(e, path);
    if (t.fd < 0)
      return -1;
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", t.fd);
    ssize_t n = readlink(proc, t.path, sizeof(t.path) - 1);
    if (n < 0) {
      SQLi_table_close(&t);
      return SQLi_fail(e, SQL_IO, "resolve table recovery path");
    }
    t.path[n] = 0;
    int rc = SQLi_lockdir(e, t.fd, 1) || sql_session_route(e, &t, 1) < 0 ||
             SQLi_recover(e, t.fd, change);
    SQLi_table_close(&t);
    return rc ? -1 : 0;
  }
  if (!strcasecmp(cmd, "show")) {
    if (SQLi_eat(p, "TRANSACTIONS"))
      return sql_transactions_list(e, p);
    if (SQLi_eat(p, "CONTEXTS"))
      return sql_context_list(e, p);
    if (SQLi_eat(p, "DEPENDENTS"))
      return sql_dep_show(e, p);
    if (SQLi_eat(p, "REFERENCES"))
      return sql_xshare_show(e, p);
    int views = SQLi_eat(p, "VIEWS");
    if (!views && SQLi_need(e, p, "TABLES"))
      return -1;
    char *path = NULL;
    if (SQLi_need(e, p, "IN"))
      return -1;
    path = take(e, p);
    if (!path)
      return -1;
    if (SQLi_end(e, p))
      return -1;
    int fd = SQLi_open_dir(e, path);
    if (fd < 0)
      return -1;
    DIR *d = fdopendir(openat(fd, ".", O_RDONLY | O_DIRECTORY));
    if (!d) {
      close(fd);
      return SQLi_fail(e, SQL_IO, "list tables");
    }
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
      if (!SQLi_component(de->d_name))
        continue;
      int sub = openat(fd, de->d_name,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (sub < 0)
        continue;
      struct stat st;
      if (!fstatat(sub, views ? ".view" : ".table", &st, AT_SYMLINK_NOFOLLOW)) {
        uint64_t generation;
        if (SQLi_lockdir(e, sub, 0) ||
            sql_object_generation(e, sub, &generation)) {
          close(sub);
          rc = -1;
          break;
        }
        SQLi_json(e->stream, (unsigned char *)de->d_name, strlen(de->d_name));
        fputc('\n', e->stream);
      }
      close(sub);
    }
    closedir(d);
    close(fd);
    return rc;
  }
  if (strcasecmp(cmd, "check") && strcasecmp(cmd, "drop") &&
      strcasecmp(cmd, "alter"))
    return SQLi_fail(e, SQL_SYNTAX, "unknown command %s", cmd);
  if (SQLi_eat(p, "VIEW")) {
    char *viewpath = NULL;
    if (p->p < p->n && !SQLi_is(p, ";") && !SQLi_is(p, "AS") &&
        !SQLi_is(p, "RESTRICT") && !SQLi_is(p, "VALIDATE") &&
        !SQLi_is(p, "INCLUDING") && !SQLi_is(p, "CASCADE") &&
        !SQLi_is(p, "PRUNE"))
      viewpath = take(e, p);
    return sql_view_cmd(e, cmd, p, viewpath);
  }
  if (SQLi_need(e, p, "TABLE"))
    return -1;
  char *path = NULL;
  const char *clauses[] = {"ALL",       "SCHEMA",   "NAMES",    "COUNTS",
                           "TYPES",     "LINKS",    "JOURNALS", "DEEP",
                           "INCLUDING", "RESTRICT", "VALIDATE", "RENAME", "CASCADE", "ADD", "DROP", "ALTER", "SET", "ADOPT",
                           NULL};
  int clause = 0;
  for (int i = 0; clauses[i]; i++)
    clause |= SQLi_is(p, clauses[i]);
  if (p->p < p->n && !SQLi_is(p, ";") && !clause)
    path = take(e, p);
  Table t = {.fd = -1};
  int rc = -1, write = strcasecmp(cmd, "check") != 0;
  if (SQLi_table_open(e, &t, path, write))
    goto done;
  if (!strcasecmp(cmd, "check")) {
    int deep = 0;
    if (SQLi_eat(p, "TYPES"))
      deep = 1;
    else if (SQLi_eat(p, "SCHEMA") || SQLi_eat(p, "NAMES") ||
             SQLi_eat(p, "COUNTS") || SQLi_eat(p, "LINKS") ||
             SQLi_eat(p, "JOURNALS") || SQLi_eat(p, "ALL")) {
    }
    if (SQLi_eat(p, "DEEP"))
      deep = 1;
    if (SQLi_end(e, p) || SQLi_scan_table(e, &t, deep))
      goto done;
    for (int i = 0; i < t.nr; i++)
      for (int j = 0; j < t.r[i].nm; j++)
        if (S_ISLNK(t.r[i].m[j].st.st_mode)) {
          char target[PATH_MAX], base[NAME_MAX + 1];
          if (SQLi_member_target(e, &t, &t.r[i].m[j], target))
            goto done;
          if (target[0] == '/') {
            struct stat anchor;
            if (sql_xshare_stat(e, target, &anchor) ||
                sql_xshare_registered(e, &t, target))
              goto done;
            continue;
          }
          int parent = sql_parentfd(e, t.fd, target, base);
          if (parent < 0)
            goto done;
          struct stat st;
          int bad = fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW) ||
                    !S_ISREG(st.st_mode);
          close(parent);
          if (bad) {
            SQLi_fail(e, SQL_CONSTRAINT, "broken/nonregular shared anchor");
            goto done;
          }
        }
    fprintf(e->stream, "ok: %d records, schema/names/counts%s\n", t.nr,
            deep ? "/types" : "");
    rc = 0;
  } else if (!strcasecmp(cmd, "drop")) {

    int purge = 0, validate = 0;
    if (SQLi_eat(p, "INCLUDING")) {
      if (SQLi_need(e, p, "DATA"))
        goto done;
      purge = 1;
    }
    if (SQLi_eat(p, "CASCADE")) {
      SQLi_fail(e, SQL_UNSUPPORTED,
                "CASCADE is deliberately not provided: dependents must be "
                "dropped explicitly; nothing changed");
      goto done;
    }
    SQLi_eat(p, "RESTRICT"); /* RESTRICT is the (only) behaviour */
    if (SQLi_eat(p, "VALIDATE")) {
      if (SQLi_need(e, p, "ONLY"))
        goto done;
      validate = 1;
    }
    if (SQLi_end(e, p))
      goto done;
    if (sql_dep_restrict(e, t.has_live_root ? t.live_root : t.fd, "DROP TABLE"))
      goto done;
    if (purge) {
      if (SQLi_scan_table(e, &t, 0))
        goto done;
      if (validate) {
        rc = 0;
        goto done;
      }
      rc = sql_purge_table(e, &t);
      goto done;
    }
    if (validate) {
      rc = 0;
      goto done;
    }
    Batch b = {.fd = -1};
    if (SQLi_batch_begin(e, t.fd, &b) ||
        SQLi_batch_op(e, &b, 'D', ".table", NULL))
      rc = -1;
    else
      rc = SQLi_batch_commit(e, &b);
    SQLi_batch_abort(&b);
  } else {
    if (SQLi_eat(p, "ADOPT")) {
      int a, x, pr;
      if (SQLi_need(e, p, "IDS") || SQLi_end(e, p))
        goto done;
      if (sql_context_active(e)) {
        SQLi_fail(e, SQL_UNSUPPORTED,
                  "ADOPT IDS is non-transactional registry metadata; run it "
                  "outside a transaction");
        goto done;
      }
      if (SQLi_scan_table(e, &t, 0) || sql_ids_adopt(e, &t, &a, &x, &pr))
        goto done;
      fprintf(e->stream, "{\"adopted\":%d,\"existing\":%d,\"pruned\":%d}\n", a,
              x, pr);
      rc = 0;
      goto done;
    }
    if (!(SQLi_is(p, "RENAME") && p->p + 1 < p->n &&
          !strcasecmp(p->t[p->p + 1].s, "RECORD"))) {
      rc = sql_alter_schema(e, &t, p);
      goto done;
    }
    if (SQLi_need(e, p, "RENAME") || SQLi_need(e, p, "RECORD"))
      goto done;
    char *old = take(e, p);
    if (!old || SQLi_need(e, p, "TO"))
      goto done;
    char *new = take(e, p);
    if (!new)
      goto done;
    int validate = 0;
    if (SQLi_eat(p, "VALIDATE")) {
      if (SQLi_need(e, p, "ONLY"))
        goto done;
      validate = 1;
    }
    if (SQLi_end(e, p) || SQLi_scan_table(e, &t, 1))
      goto done;
    if (SQLi_schema_record_path(e, &t.schema, new) < 0)
      goto done;
    Record *r = NULL;
    for (int i = 0; i < t.nr; i++)
      if (!strcmp(t.r[i].path, old))
        r = &t.r[i];
    if (!r) {
      SQLi_fail(e, SQL_CONSTRAINT, "unknown record");
      goto done;
    }
    /* One RECORD schema boundary fixes directory depth, so relative shared
       anchors remain valid when moving between matching parent groups. */
    char destination[NAME_MAX + 1];
    int destination_parent = sql_parentfd(e, t.fd, new, destination);
    if (destination_parent < 0)
      goto done;
    close(destination_parent);
    struct stat st;
    if (!fstatat(t.fd, new, &st, AT_SYMLINK_NOFOLLOW)) {
      SQLi_fail(e, SQL_CONSTRAINT, "destination exists");
      goto done;
    }
    Batch b = {.fd = -1};
    if (SQLi_batch_begin(e, t.fd, &b) || SQLi_batch_op(e, &b, 'T', old, new))
      rc = -1;
    else if (validate)
      rc = sql_batch_prepare(e, &b) || sql_preflight(e, &b) ? -1 : 0;
    else
      rc = SQLi_batch_commit(e, &b);
    SQLi_batch_abort(&b);
  }
done:
  SQLi_table_close(&t);
  return rc;
}
