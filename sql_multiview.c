/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Named independent LINKED branches. No schema union or cross-source atomicity.
 */
#include "sql_local.h"
static int name_ok(const char *s) {
  if (!s || !isalpha((unsigned char)*s) || strlen(s) >= 64)
    return 0;
  for (; *s; s++)
    if (!isalnum((unsigned char)*s) && *s != '_' && *s != '-')
      return 0;
  return 1;
}
int sql_multiview_kind(Env *e, int root) {
  int fd = sql_regular_open(e, root, ".view", 0, NULL);
  if (fd < 0)
    return -1;
  uint32_t h[3];
  int bad = sql_read_all(fd, h, sizeof(h));
  close(fd);
  if (bad)
    return SQLi_fail(e, SQL_CONSTRAINT, "short view header");
  return h[0] == SQL_VIEW_MAGIC && h[1] == 3 ? 1 : 0;
}
static int child(Env *e, int root, SQL_ViewBranch *b) {
  int fd =
      openat(root, b->Name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat st;
  SQL_ViewMap v;
  if (fd < 0)
    return SQLi_fail(e, SQL_CONSTRAINT, "missing real branch directory");
  if (fstat(fd, &st) || st.st_dev != b->Device || st.st_ino != b->Inode ||
      sql_view_read(e, fd, &v) || v.version != 2 ||
      v.Device != b->View.Device || v.Inode != b->View.Inode ||
      strcmp(v.Source, b->View.Source) || strcmp(v.Query, b->View.Query)) {
    close(fd);
    return SQLi_fail(
        e, SQL_CONSTRAINT,
        "branch identity/definition changed; root manifest not retargeted");
  }
  return fd;
}
int sql_multiview_read(Env *e, int root, SQL_MultiView *m) {
  struct stat st, dir;
  int fd = sql_regular_open(e, root, ".view", 0, &st);
  if (fd < 0)
    return -1;
  if (st.st_size != sizeof(*m) || st.st_uid != getuid() ||
      (st.st_mode & 0077)) {
    close(fd);
    return SQLi_fail(e, SQL_CONSTRAINT, "multi-view size/privacy mismatch");
  }
  void *p = sql_mapping(e, fd, sizeof(*m), 0);
  if (!p) {
    close(fd);
    return -1;
  }
  memcpy(m, p, sizeof(*m));
  sql_unmapping(p);
  close(fd);
  if (fstat(root, &dir) || m->magic != SQL_VIEW_MAGIC || m->version != 3 ||
      m->bytes != sizeof(*m) || m->endian != 0x01020304 || m->flags != 1 ||
      m->generation != 1 || m->UID != getuid() || m->Device != dir.st_dev ||
      m->Inode != dir.st_ino || !m->Count || m->Count > SQL_BRANCH_MAX)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid multi-view identity/version/count");
  for (unsigned i = 0; i < m->Count; i++) {
    SQL_ViewBranch *b = &m->Branch[i];
    if (!memchr(b->Name, 0, sizeof(b->Name)) || !name_ok(b->Name) ||
        !b->Inode || b->View.version != 2 || sql_view_validate(e, &b->View))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid branch descriptor");
    for (unsigned j = 0; j < i; j++)
      if (!strcmp(b->Name, m->Branch[j].Name))
        return SQLi_fail(e, SQL_CONSTRAINT, "duplicate branch name");
  }
  return 0;
}
int sql_multiview_sources(Env *e, int root, SQL_ViewMap *maps) {
  int kind = sql_multiview_kind(e, root);
  if (kind <= 0)
    return kind;
  SQL_MultiView *m = malloc(sizeof(*m));
  if (!m)
    return SQLi_fail(e, SQL_IO, "multi-view allocation");
  int count = -1;
  if (sql_multiview_read(e, root, m))
    goto done;
  for (unsigned i = 0; i < m->Count; i++) {
    int fd = child(e, root, &m->Branch[i]);
    if (fd < 0)
      goto done;
    close(fd);
    maps[i] = m->Branch[i].View;
  }
  count = m->Count;
done:
  free(m);
  return count;
}
static int write_map(Env *e, int root, SQL_MultiView *m) {
  char id[33], tmp[80];
  if (sql_uuid(e, id))
    return -1;
  snprintf(tmp, sizeof(tmp), ".sql-multi.%s", id);
  int fd = openat(root, tmp, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "multi-view private map");
  int rc = -1;
  void *p = NULL;
  if (ftruncate(fd, sizeof(*m)))
    goto done;
  p = sql_mapping(e, fd, sizeof(*m), PROT_WRITE);
  if (!p)
    goto done;
  memcpy(p, m, sizeof(*m));
  UpdateMap(p, sizeof(*m));
  int bad = msync(p, sizeof(*m), MS_SYNC) || fsync(fd);
  sql_unmapping(p);
  p = NULL;
  if (bad || renameat2(root, tmp, root, ".view", RENAME_NOREPLACE) ||
      fsync(root))
    goto done;
  rc = 0;
done:
  if (p)
    sql_unmapping(p);
  close(fd);
  unlinkat(root, tmp, 0);
  return rc ? SQLi_fail(e, SQL_IO,
                        "multi-view map publication failed; branch directories "
                        "preserved")
            : 0;
}
static int refresh_child(Env *e, int fd) {
  Env local = *e;
  SQL_Result out = {0};
  local.out = &out;
  local.status = 0;
  local.pinned_view_fd = fd + 1;
  Table t = {.fd = -1};
  int rc = sql_relation_open(&local, &t, NULL);
  SQLi_table_close(&t);
  return rc ? (local.status ? local.status : SQL_IO) : 0;
}
int sql_multiview_reconcile(Env *e, int root) {
  SQL_MultiView *m = malloc(sizeof(*m));
  if (!m)
    return SQL_IO;
  if (sql_multiview_read(e, root, m)) {
    free(m);
    return e->status;
  }
  int status = 0;
  for (unsigned i = 0; i < m->Count; i++) {
    int fd = child(e, root, &m->Branch[i]);
    if (fd < 0) {
      status = e->status;
      break;
    }
    int result = refresh_child(e, fd);
    close(fd);
    if (result && !status)
      status = result;
  }
  free(m);
  return status;
}
int sql_multiview_create(Env *e, Parser *p, const char *path) {
  if (e->opt.binding_count)
    return SQLi_fail(e, SQL_UNSUPPORTED,
                     "named branch definitions do not capture runtime "
                     "bindings; use literal definitions");

  SQL_MultiView *m = calloc(1, sizeof(*m));
  SQL_QueryResult *q = calloc(1, sizeof(*q));
  Parser *sub = calloc(1, sizeof(*sub));
  if (!m || !q || !sub) {
    free(m);
    free(q);
    free(sub);
    return SQLi_fail(e, SQL_IO, "branch construction allocation");
  }
  int root = -1, rc = -1;
  if (SQLi_need(e, p, "("))
    goto done;
  do {
    if (m->Count == SQL_BRANCH_MAX) {
      SQLi_fail(e, SQL_CONSTRAINT, "branch limit 8");
      goto done;
    }
    char *name = take(e, p);
    if (!name_ok(name)) {
      SQLi_fail(
          e, SQL_SYNTAX,
          "branch names start with letter, then letters/digits/_/- (max 63)");
      goto done;
    }
    for (unsigned i = 0; i < m->Count; i++)
      if (!strcmp(name, m->Branch[i].Name)) {
        SQLi_fail(e, SQL_CONSTRAINT, "duplicate branch name");
        goto done;
      }
    if (SQLi_need(e, p, "AS") || SQLi_need(e, p, "SELECT"))
      goto done;
    int start = p->p, depth = 0;
    while (p->p < p->n) {
      Tok *t = &p->t[p->p];
      if (!t->quoted) {
        if (!strcmp(t->s, "("))
          depth++;
        else if (!strcmp(t->s, ")")) {
          if (!depth)
            break;
          depth--;
        } else if (!strcmp(t->s, ";") && !depth)
          break;
      }
      p->p++;
    }
    char text[DDL_SIZE];
    if (sql_tokens_text(e, p, start, p->p, text, sizeof(text)))
      goto done;
    q->linked_fd = -1;
    if (SQLi_lex(e, sub, text) || sql_query(e, sub, q))
      goto done;
    SQL_ViewBranch *b = &m->Branch[m->Count++];
    strcpy(b->Name, name);
    b->View = (SQL_ViewMap){.magic = SQL_VIEW_MAGIC,
                            .version = 2,
                            .bytes = sizeof(SQL_ViewMap),
                            .endian = 0x01020304,
                            .reserved = 1,
                            .generation = 1,
                            .Device = q->device,
                            .Inode = q->inode};
    strcpy(b->View.Source, q->source);
    strcpy(b->View.Query, q->query);
    sql_query_free(q);
    SQLi_parser_free(sub);
  } while (SQLi_eat(p, ";"));
  if (SQLi_need(e, p, ")") || SQLi_end(e, p))
    goto done;
  root = sql_view_directory(e, path, 1);
  if (root < 0 || SQLi_lockdir(e, root, 1))
    goto done;
  DIR *dir = fdopendir(openat(root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!dir) {
    SQLi_fail(e, SQL_IO, "inspect multi-view directory");
    goto done;
  }
  struct dirent *de;
  int nonempty = 0;
  while ((de = readdir(dir)))
    if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") &&
        !sql_provisioned_metadata(e, root, de->d_name))
      nonempty = 1;
  closedir(dir);
  if (nonempty) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "multi-view creation requires empty directory; preserved");
    goto done;
  }
  struct stat identity;
  if (fstat(root, &identity))
    goto done;
  m->magic = SQL_VIEW_MAGIC;
  m->version = 3;
  m->bytes = sizeof(*m);
  m->endian = 0x01020304;
  m->flags = 1;
  m->generation = 1;
  m->Device = identity.st_dev;
  m->Inode = identity.st_ino;
  m->UID = getuid();
  for (unsigned i = 0; i < m->Count; i++) {
    SQL_ViewBranch *b = &m->Branch[i];
    if (mkdirat(root, b->Name, 0700)) {
      SQLi_fail(e, SQL_IO, "create branch directory");
      goto done;
    }
    int fd =
        openat(root, b->Name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
      goto done;
    int bad = fstat(fd, &identity) ||
              sql_dep_register(e, b->View.Source, "view", fd) ||
              sql_view_write(e, fd, &b->View, 0);
    if (!bad) {
      b->Device = identity.st_dev;
      b->Inode = identity.st_ino;
      int status = refresh_child(e, fd);
      if (status) {
        SQLi_fail(e, status,
                  "initial branch refresh failed; owned directories preserved");
        bad = 1;
      }
    }
    close(fd);
    if (bad)
      goto done;
  }
  if (fsync(root))
    goto done;
  rc = write_map(e, root, m);
done:
  if (root >= 0)
    close(root);
  SQLi_parser_free(sub);
  sql_query_free(q);
  free(sub);
  free(q);
  free(m);
  if (rc && !e->status)
    SQLi_fail(e, SQL_IO,
              "multi-view construction failed; no unrelated files removed");
  return rc;
}
static int definition(Env *e, SQL_MultiView *m, char **out) {
  size_t len = 0;
  FILE *f = open_memstream(out, &len);
  if (!f)
    return SQLi_fail(e, SQL_IO, "branch definition buffer");
  fputc('(', f);
  for (unsigned i = 0; i < m->Count; i++) {
    if (i)
      fputs(" ; ", f);
    fprintf(f, "%s AS SELECT %s", m->Branch[i].Name, m->Branch[i].View.Query);
  }
  fputc(')', f);
  if (fclose(f) || len > 65535) {
    free(*out);
    *out = NULL;
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "branch definition exceeds replay bound");
  }
  return 0;
}
int sql_multiview_admin(Env *e, int root, const char *cmd, Parser *p) {
  SQL_MultiView *m = malloc(sizeof(*m));
  if (!m)
    return SQLi_fail(e, SQL_IO, "multi-view allocation");
  int rc = -1;
  if (SQLi_lockdir(e, root, !strcasecmp(cmd, "drop")) ||
      sql_multiview_read(e, root, m))
    goto done;
  if (!strcasecmp(cmd, "describe")) {
    int ddl = SQLi_eat(p, "AS");
    if ((ddl && SQLi_need(e, p, "DDL")) || SQLi_end(e, p))
      goto done;
    char *text = NULL;
    if (definition(e, m, &text))
      goto done;
    fprintf(e->stream, "%s%s\n", ddl ? "VIEW LINKED BRANCHES " : "BRANCHES ",
            text);
    free(text);
    rc = 0;
  } else if (!strcasecmp(cmd, "check")) {
    if (SQLi_end(e, p))
      goto done;
    int status = sql_multiview_reconcile(e, root);
    rc = status ? SQLi_fail(e, status, "branch check failed") : 0;
  } else if (!strcasecmp(cmd, "drop")) {
    int purge = 0;
    if (SQLi_eat(p, "INCLUDING")) {
      if (SQLi_need(e, p, "DATA"))
        goto done;
      purge = 1;
    }
    if (SQLi_eat(p, "CASCADE")) {
      SQLi_fail(e, SQL_UNSUPPORTED,
                "CASCADE is deliberately not provided; nothing changed");
      goto done;
    }
    SQLi_eat(p, "RESTRICT");
    int dry = SQLi_eat(p, "VALIDATE");
    if ((dry && SQLi_need(e, p, "ONLY")) || SQLi_end(e, p))
      goto done;
    if (sql_dep_restrict(e, root, "DROP VIEW"))
      goto done;
    rc = dry     ? 0
         : purge ? sql_purge_multiview(e, root, m)
                 : (unlinkat(root, ".view", 0) || fsync(root)
                        ? SQLi_fail(e, SQL_IO, "drop root definition")
                        : 0);
  } else
    SQLi_fail(e, SQL_SYNTAX, "unsupported multi-view administration");
done:
  free(m);
  return rc;
}
int sql_multiview_select(Env *e, Parser *p) {
  char *name = take(e, p);
  if (!name || !name_ok(name))
    return SQLi_fail(e, SQL_SYNTAX, "invalid explicit branch name");
  /* Inside a transaction the branch definition is read from the live root
   * (multi-view DDL is refused in transactions, so it cannot be staged) and
   * the branch query routes its source table through the transaction, so
   * the read sees this transaction's staged writes. */
  for (int i = p->p; i < p->n; i++)
    if (!p->t[i].quoted && !strcasecmp(p->t[i].s, "FROM"))
      return SQLi_fail(e, SQL_SYNTAX,
                       "SELECT BRANCH uses selected branch; omit FROM or query "
                       "branch path directly");
  int root = SQLi_open_dir(e, NULL), fd = -1, definition_fd = -1, rc = -1;
  SQL_MultiView *m = malloc(sizeof(*m));
  SQL_TraceScope trace = {0};
  char saved[PATH_MAX];
  strcpy(saved, e->cwd);
  if (!m) {
    SQLi_fail(e, SQL_IO, "multi-view allocation");
    goto done;
  }
  if (root < 0 || SQLi_lockdir(e, root, 0) || sql_multiview_read(e, root, m))
    goto done;
  for (unsigned i = 0; i < m->Count; i++)
    if (!strcmp(name, m->Branch[i].Name)) {
      fd = child(e, root, &m->Branch[i]);
      break;
    }
  if (fd < 0) {
    if (!e->status)
      SQLi_fail(e, SQL_CONSTRAINT, "unknown branch");
    goto done;
  }
  if (SQLi_joinpath(e, e->cwd, saved, name))
    goto done;
  definition_fd = sql_regular_open(e, root, ".view", 0, NULL);
  if (definition_fd < 0 ||
      sql_trace_map(e, definition_fd, sizeof(*m),
                    offsetof(SQL_MultiView, TraceLevel), 0, &trace))
    goto done;
  e->pinned_view_fd = fd + 1;
  rc = sql_query(e, p, NULL);
done:
  e->pinned_view_fd = 0;
  strcpy(e->cwd, saved);
  sql_trace_unmap(&trace);
  if (definition_fd >= 0)
    close(definition_fd);
  if (fd >= 0)
    close(fd);
  if (root >= 0)
    close(root);
  free(m);
  return rc;
}
#define STRUCT SQL_ViewMap
static Mitem query_items[] = {U64_(DISPLAY_ONLY, Device, "source device"),
                              U64_(DISPLAY_ONLY, Inode, "source inode"),
                              String_(DISPLAY_ONLY, Source, "canonical source"),
                              String_(DISPLAY_ONLY, Query, "saved query"),
                              {0}};
#undef STRUCT
#define STRUCT SQL_ViewBranch
static Mitem branch_items[] = {
    String_(DISPLAY_ONLY, Name, "branch name"),
    U64_(DISPLAY_ONLY, Device, "branch directory device"),
    U64_(DISPLAY_ONLY, Inode, "branch directory inode"),
    Struct(SQL_ViewMap, View, query_items),
    {0}};
#undef STRUCT
#define STRUCT SQL_MultiView
static Mitem multi_items[] = {
    U32_(DISPLAY_ONLY, magic, "view magic"),
    U32_(DISPLAY_ONLY, version, "format"),
    U32_(DISPLAY_ONLY, bytes, "native size"),
    U32_(DISPLAY_ONLY, endian, "endian"),
    U32(TraceLevel, "live shared Trace"),
    U32_(DISPLAY_ONLY, flags, "named branches"),
    U64_(DISPLAY_ONLY, generation, "definition generation"),
    U64_(DISPLAY_ONLY, Device, "root device"),
    U64_(DISPLAY_ONLY, Inode, "root inode"),
    U32_(DISPLAY_ONLY, UID, "owner"),
    U32_(DISPLAY_ONLY, Count, "branch count"),
    Struct(SQL_ViewBranch, Branch, branch_items),
    {0}};
#undef STRUCT
int sql_multiview_mem(int ac, char **av) {
  SQL_Result out = {0};
  Env e = {.out = &out};
  if (!getcwd(e.cwd, sizeof(e.cwd)))
    return SQL_IO;
  int root = SQLi_open_dir(&e, av[1]), fd = -1, rc = -1;
  SQL_MultiView *m = malloc(sizeof(*m));
  char *text = NULL;
  if (!m) {
    SQLi_fail(&e, SQL_IO, "multi-view allocation");
    goto done;
  }
  if (root < 0 || SQLi_lockdir(&e, root, 0) ||
      sql_multiview_read(&e, root, m) || definition(&e, m, &text))
    goto done;
  if (ac == 4) {
    if (!strcmp(av[2], "C.Definition")) {
      rc = strcmp(av[3], text)
               ? SQLi_fail(&e, SQL_CONSTRAINT,
                           "branch definitions immutable in this slice; replay "
                           "must match exactly")
               : 0;
    } else if (!strcmp(av[2], "C.TraceLevel")) {
      char *end;
      errno = 0;
      unsigned long long value = strtoull(av[3], &end, 0);
      if (!*av[3] || *av[3] == '-' || *end || errno || value > UINT32_MAX) {
        SQLi_fail(&e, SQL_SYNTAX, "TraceLevel uint32 required");
        goto done;
      }
      char number[32];
      snprintf(number, sizeof(number), "%u", (unsigned)value);
      Input_Memory_Item(m, multi_items, "TraceLevel", number);
      if (m->TraceLevel != value) {
        SQLi_fail(&e, SQL_CONSTRAINT, "mio conversion mismatch");
        goto done;
      }
      fd = sql_regular_open(&e, root, ".view", 1, NULL);
      if (fd >= 0 && !SQLi_lockdir(&e, fd, 1))
        rc = sql_trace_store(&e, fd, sizeof(*m),
                             offsetof(SQL_MultiView, TraceLevel), value);
    } else
      SQLi_fail(&e, SQL_SYNTAX, "unknown/read-only multi-view variable");
  } else {
    fprintf(stdout,
            "#!/bin/sh\n# C.version=3 C.Count=%u C.UID=%u C.Device=%llu "
            "C.Inode=%llu; identity read-only\n",
            m->Count, m->UID, (unsigned long long)m->Device,
            (unsigned long long)m->Inode);
    fprintf(
        stdout,
        "# C.magic=%u C.bytes=%u C.endian=%u C.flags=%u C.generation=%llu\n",
        m->magic, m->bytes, m->endian, m->flags,
        (unsigned long long)m->generation);
    for (unsigned i = 0; i < m->Count; i++) {
      SQL_ViewBranch *b = &m->Branch[i];
      fprintf(stdout,
              "# C.Branch[%u].Name=%s Device=%llu Inode=%llu SourceDevice=%llu "
              "SourceInode=%llu\n# Source=",
              i, b->Name, (unsigned long long)b->Device,
              (unsigned long long)b->Inode, (unsigned long long)b->View.Device,
              (unsigned long long)b->View.Inode);
      SQLi_json(stdout, (unsigned char *)b->View.Source,
                strlen(b->View.Source));
      fputs("\n# Query=", stdout);
      SQLi_json(stdout, (unsigned char *)b->View.Query, strlen(b->View.Query));
      fputc('\n', stdout);
    }
    fputs("sql_viewmem ", stdout);
    SQLi_shellquote(stdout, av[1]);
    fprintf(stdout, " C.TraceLevel '%u'\nsql_viewmem ", m->TraceLevel);
    SQLi_shellquote(stdout, av[1]);
    fputs(" C.Definition ", stdout);
    SQLi_shellquote(stdout, text);
    fputc('\n', stdout);
    rc = ferror(stdout) || fflush(stdout) ? SQL_IO : 0;
  }
done:
  if (e.status)
    fprintf(stderr, "sql_viewmem: %s\n", out.diagnostic);
  if (fd >= 0)
    close(fd);
  if (root >= 0)
    close(root);
  free(text);
  free(m);
  return e.status ? (int)e.status : rc < 0 ? SQL_IO : rc;
}
