/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
#include "sql_trigger_meta.h"
static void quote(FILE *f, const char *s) {
  fputc('\'', f);
  for (; *s; s++) {
    if (*s == '\'')
      fputc('\'', f);
    fputc(*s, f);
  }
  fputc('\'', f);
}
int sql_trg_definition(Env *e, SQL_TriggerDef *d) {
  char *text = NULL, where[sizeof(d->Definition)];
  size_t length = 0;
  snprintf(where, sizeof(where), "%s", sql_trg_where(d));
  FILE *f = open_memstream(&text, &length);
  if (!f)
    return SQLi_fail(e, SQL_IO, "trigger definition buffer");
  fputs("CREATE ", f);
  quote(f, d->Name);
  fputs(" AFTER ", f);
  if (d->Kind == SQL_EVENT_ALL)
    fputs("COMMIT", f);
  else {
    const char *names[] = {"INSERT", "UPDATE", "DELETE", "LINK",
                           "UNLINK", "RENAME"};
    int first = 1;
    for (int i = 0; i < 6; i++)
      if (d->Kind & (1u << i)) {
        if (!first)
          fputc(',', f);
        first = 0;
        fputs(names[i], f);
      }
  }
  if (d->FieldCount) {
    fputs(" OF (", f);
    for (unsigned i = 0; i < d->FieldCount; i++) {
      if (i)
        fputc(',', f);
      quote(f, d->Fields[i]);
    }
    fputc(')', f);
  }
  if (*where)
    fprintf(f, " WHERE %s", where);
  fputs(" EXECUTE ", f);
  quote(f, d->Exec);
  fputs(" ARGUMENTS (", f);
  for (unsigned i = 0; i < d->ArgCount; i++) {
    if (i)
      fputc(',', f);
    quote(f, d->Args[i]);
  }
  fprintf(f, ") TIMEOUT %u RETRIES %u %s", d->Timeout, d->Retries,
          d->Enabled ? "ENABLED" : "DISABLED");
  int bad = fclose(f) ||
            length + 1 + strlen(where) + 1 > sizeof(d->Definition);
  if (!bad) {
    memset(d->Definition, 0, sizeof(d->Definition));
    memcpy(d->Definition, text, length + 1);
    memcpy(d->Definition + length + 1, where, strlen(where) + 1);
  }
  free(text);
  return bad ? SQLi_fail(e, SQL_CONSTRAINT, "trigger definition length bound")
             : 0;
}
int sql_trigger_cmd(Env *e, const char *cmd, Parser *p) {
  if (!strcasecmp(cmd, "watch"))
    return sql_watch_engine(e, p);
  int create = SQLi_eat(p, "CREATE"), init = 0, show = 0, enable = 0,
      disable = 0, drop = 0;
  char *name = NULL, *path = NULL;
  SQL_TriggerDef def = {0};
  if (create) {
    if (sql_trg_parse(e, p, &def, &path))
      return -1;
    name = def.Name;
  } else {
    init = SQLi_eat(p, "INIT");
    show = !init && SQLi_eat(p, "SHOW");
    enable = !init && !show && SQLi_eat(p, "ENABLE");
    disable = !init && !show && !enable && SQLi_eat(p, "DISABLE");
    drop = !init && !show && !enable && !disable && SQLi_eat(p, "DROP");
    if (!init && !show && !enable && !disable && !drop)
      return SQLi_fail(e, SQL_SYNTAX,
                       "TRIGGER requires INIT/CREATE/SHOW/ENABLE/DISABLE/DROP");
    if (!init && !show) {
      name = take(e, p);
      if (!name)
        return -1;
    }
    if (SQLi_eat(p, "ON")) {
      path = take(e, p);
      if (!path)
        return -1;
    }
    if (SQLi_end(e, p))
      return -1;
  }
  if (!show && sql_context_active(e))
    return SQLi_fail(e, SQL_UNSUPPORTED,
                     "transactional trigger DDL is not yet implemented");
  int root = SQLi_open_dir(e, path), fd = -1, rc = -1;
  SQL_TriggerMap *m = malloc(sizeof(*m));
  SQL_Map table;
  if (!m) {
    if (root >= 0)
      close(root);
    return SQLi_fail(e, SQL_IO, "trigger map allocation");
  }
  if (root < 0 || SQLi_lockdir(e, root, !show) || SQLi_pending(e, root) ||
      SQLi_map_read(e, root, ".table", &table))
    goto done;
  if (create && sql_trg_fields(e, root, &def))
    goto done;
  fd = sql_trg_open(e, root, create || init);
  if (fd < 0 || SQLi_lockdir(e, fd, !show) || sql_trg_read(e, fd, m))
    goto done;
  if (show) {
    uint64_t skipped[SQL_TRG_MAX];
    if (sql_trg_skipped(e, fd, m, skipped))
      goto done;
    fputc('[', e->stream);
    int first = 1;
    for (unsigned i = 0; i < m->Count; i++) {
      SQL_TriggerDef *d = &m->Trigger[i];
      if (!d->Used)
        continue;
      if (!first)
        fputc(',', e->stream);
      first = 0;
      fputs("{\"name\":", e->stream);
      SQLi_json(e->stream, (unsigned char *)d->Name, strlen(d->Name));
      fprintf(e->stream,
              ",\"enabled\":%s,\"checkpoint\":%llu,\"delivered\":%llu,"
              "\"skipped\":%llu,\"failures\":%llu,\"status\":%u",
              d->Enabled ? "true" : "false", (unsigned long long)d->Checkpoint,
              (unsigned long long)d->Delivered, (unsigned long long)skipped[i],
              (unsigned long long)d->Failures, d->LastStatus);
      if (*sql_trg_where(d)) {
        fputs(",\"where\":", e->stream);
        SQLi_json(e->stream, (unsigned char *)sql_trg_where(d),
                  strlen(sql_trg_where(d)));
      }
      fputc('}', e->stream);
    }
    fputs("]\n", e->stream);
    rc = 0;
    goto done;
  }
  if (init) {
    rc = 0;
    goto done;
  }
  unsigned slot = m->Count;
  for (unsigned i = 0; i < m->Count; i++)
    if (m->Trigger[i].Used && !strcmp(m->Trigger[i].Name, name)) {
      slot = i;
      break;
    }
  if (create) {
    if (slot < m->Count) {
      SQLi_fail(e, SQL_CONSTRAINT, "trigger already exists");
      goto done;
    }
    for (unsigned i = 0; i < m->Count; i++)
      if (!m->Trigger[i].Used) {
        slot = i;
        break;
      }
    if (slot == m->Count) {
      SQLi_fail(e, SQL_CONSTRAINT, "trigger registration limit 16");
      goto done;
    }
    def.Checkpoint = table.generation;
    if (sql_trg_definition(e, &def))
      goto done;
    m->Trigger[slot] = def;
  } else {
    if (slot == m->Count) {
      SQLi_fail(e, SQL_CONSTRAINT, "unknown trigger");
      goto done;
    }
    if (drop)
      memset(&m->Trigger[slot], 0, sizeof(m->Trigger[slot]));
    else {
      m->Trigger[slot].Enabled = enable;
      if (sql_trg_definition(e, &m->Trigger[slot]))
        goto done;
    }
  }
  rc = sql_trg_save(e, fd, m);
done:
  if (fd >= 0)
    close(fd);
  if (root >= 0)
    close(root);
  free(m);
  return rc;
}
