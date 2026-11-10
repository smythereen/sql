/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* ALTER TABLE schema evolution.  Every form rewrites the canonical DDL from a
 * parsed Schema, re-parses it (so the result obeys every CREATE rule) and
 * journals the new .table together with any data migration in ONE batch;
 * the batch preflight then validates the complete final tree against the new
 * DDL before the decision, so a refused ALTER changes nothing. */
#include "sql_local.h"
static void quote(FILE *f, const char *s) {
  fputc('\'', f);
  for (; *s; s++) {
    if (*s == '\'')
      fputc('\'', f);
    fputc(*s, f);
  }
  fputc('\'', f);
}
static void node_text(FILE *f, Schema *s, int id) {
  Node *n = &s->node[id];
  fprintf(f, "%s %s", n->name, n->type);
  if (n->max < 0)
    fprintf(f, " [%d-]", n->min);
  else
    fprintf(f, " [%d-%d]", n->min, n->max);
  if (n->record)
    fputs(" RECORD", f);
  if (n->format[0]) {
    fputs(" FORMAT ", f);
    quote(f, n->format);
  }
  if (n->match[0]) {
    fputs(" MATCH ", f);
    quote(f, n->match);
  }
  if (n->nc) {
    fputs(" CAPTURE (", f);
    for (int i = 0; i < n->nc; i++)
      fprintf(f, "%s%s %s", i ? ", " : "", n->cap[i], n->captype[i]);
    fputc(')', f);
  }
  if (n->notnull)
    fputs(" NOT NULL", f);
  if (n->strict)
    fputs(" STRICT", f);
  if (n->hasdefault) {
    fputs(" DEFAULT ", f);
    if (n->defnull)
      fputs("NULL", f);
    else
      quote(f, n->def);
  }
  if (!strcmp(n->type, "DIRECTORY")) {
    fputs(" (", f);
    int first = 1;
    for (int i = 0; i < s->n; i++)
      if (s->node[i].parent == id) {
        fputs(first ? "" : ", ", f);
        first = 0;
        node_text(f, s, i);
      }
    fputc(')', f);
  }
}
int sql_schema_serialize(Env *e, Schema *s, char *out, size_t z) {
  char *b = NULL;
  size_t len = 0;
  FILE *f = open_memstream(&b, &len);
  if (!f)
    return SQLi_fail(e, SQL_IO, "out of memory");
  fputc('(', f);
  int first = 1;
  for (int i = 0; i < s->n; i++)
    if (s->node[i].parent < 0) {
      fputs(first ? "" : ", ", f);
      first = 0;
      node_text(f, s, i);
    }
  fprintf(f, ") UNMATCHED %s LINKS %s", s->unmatched ? "IGNORE" : "ERROR",
          s->links ? "INTERNAL" : "REJECT");
  fclose(f);
  if (len >= z) {
    free(b);
    return SQLi_fail(e, SQL_CONSTRAINT, "altered schema exceeds 16KiB");
  }
  memcpy(out, b, len + 1);
  free(b);
  return 0;
}
static int record_node(Schema *s) {
  for (int i = 0; i < s->n; i++)
    if (s->node[i].record)
      return i;
  return -1;
}
static int restricted(Env *e, Table *t, const char *field, const char *what) {
  int n = sql_dep_scan(e, t->has_live_root ? t->live_root : t->fd, 1, NULL,
                     field);
  if (n < 0)
    return -1;
  return n ? SQLi_fail(e, SQL_CONSTRAINT,
                       "%s refused (RESTRICT): %d live dependent view(s) "
                       "reference %s; drop or redefine them first",
                       what, n, field)
           : 0;
}
static int nullmarker(char *out, const char *path) {
  const char *slash = strrchr(path, '/');
  return snprintf(out, PATH_MAX, "%.*s/.sql-null.%s", (int)(slash - path), path,
                  slash + 1) >= PATH_MAX;
}
int sql_alter_schema(Env *e, Table *t, Parser *p) {
  Schema ns = {0}, fin = {0};
  Batch b = {.fd = -1};
  int rc = -1, validate = 0, deep = 0;
  char text[DDL_SIZE];
  if (SQLi_schema_text(e, t->map.DDL, &ns))
    goto done;
  if (SQLi_scan_table(e, t, 0))
    goto done;
  if (SQLi_batch_begin(e, t->fd, &b))
    goto done;
  int rec = record_node(&ns);
  if (SQLi_eat(p, "ADD")) {
    if (SQLi_need(e, p, "FIELD"))
      goto done;
    /* Parse the declaration exactly as CREATE would, inside a probe RECORD. */
    int start = p->p, stop = p->n;
    for (int i = start; i < p->n; i++)
      if (!p->t[i].quoted && !strcasecmp(p->t[i].s, "VALIDATE"))
        stop = i;
    char decl[DDL_SIZE], probe[DDL_SIZE + 64];
    if (sql_tokens_text(e, p, start, stop, decl, sizeof(decl)))
      goto done;
    snprintf(probe, sizeof(probe), "(sql_alter_probe DIRECTORY RECORD (%s))",
             decl);
    Schema one = {0};
    if (SQLi_schema_text(e, probe, &one)) {
      SQLi_schema_free(&one);
      goto done;
    }
    if (one.n != 2) {
      SQLi_schema_free(&one);
      SQLi_fail(e, SQL_SYNTAX, "ADD FIELD takes exactly one field declaration");
      goto done;
    }
    if (ns.n >= NODES) {
      SQLi_schema_free(&one);
      SQLi_fail(e, SQL_CONSTRAINT, "maximum 64 schema nodes");
      goto done;
    }
    Node *n = &ns.node[ns.n++];
    *n = one.node[1];
    n->compiled = 0; /* regex rebuilt by the final re-parse */
    memset(&n->re, 0, sizeof(n->re));
    n->parent = rec;
    SQLi_schema_free(&one);
    p->p = stop;
    if (n->min > 0 && t->nr) {
      if (!n->hasdefault) {
        SQLi_fail(e, SQL_CONSTRAINT,
                  "ADD FIELD %s [%d-...] on %d existing record(s) requires "
                  "DEFAULT or minimum 0",
                  n->name, n->min, t->nr);
        goto done;
      }
      for (int i = 0; i < t->nr; i++)
        for (int k = 1; k <= n->min; k++) {
          char name[NAME_MAX + 1], path[PATH_MAX], marker[PATH_MAX];
          if (SQLi_field_filename_at(e, &ns, n, t->r[i].path, k, name,
                                     sizeof(name)) ||
              SQLi_joinpath(e, path, t->r[i].path, name))
            goto done;
          const char *v = n->defnull ? "" : n->def;
          if (SQLi_batch_put(e, &b, path, v, strlen(v)))
            goto done;
          if (n->defnull && (nullmarker(marker, path) ||
                             SQLi_batch_put(e, &b, marker, "", 0)))
            goto done;
        }
    }
  } else if (SQLi_eat(p, "DROP")) {
    if (SQLi_need(e, p, "FIELD"))
      goto done;
    char *name = take(e, p);
    if (!name)
      goto done;
    int purge = 0;
    if (SQLi_eat(p, "INCLUDING")) {
      if (SQLi_need(e, p, "DATA"))
        goto done;
      purge = 1;
    }
    int id = SQLi_field_id(&ns, name);
    if (id < 0 || !strcmp(ns.node[id].type, "DIRECTORY")) {
      SQLi_fail(e, SQL_SYNTAX, "DROP FIELD requires an existing leaf field");
      goto done;
    }
    if (restricted(e, t, name, "DROP FIELD"))
      goto done;
    int members = 0;
    for (int i = 0; i < t->nr; i++)
      for (int j = 0; j < t->r[i].nm; j++) {
        Member *m = &t->r[i].m[j];
        if (m->field != id)
          continue;
        members++;
        if (!purge)
          continue;
        char marker[PATH_MAX];
        if (SQLi_batch_op(e, &b, 'D', m->path, NULL) ||
            (m->isnull && (nullmarker(marker, m->path) ||
                           SQLi_batch_op(e, &b, 'D', marker, NULL))))
          goto done;
      }
    if (members && !purge) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "field %s still has %d member(s); use DROP FIELD %s INCLUDING "
                "DATA",
                name, members, name);
      goto done;
    }
    /* Remove node id, renumbering parents. */
    if (ns.node[id].compiled)
      regfree(&ns.node[id].re);
    memmove(&ns.node[id], &ns.node[id + 1], (ns.n - id - 1) * sizeof(Node));
    ns.n--;
    for (int i = 0; i < ns.n; i++)
      if (ns.node[i].parent > id)
        ns.node[i].parent--;
  } else if (SQLi_eat(p, "RENAME")) {
    int capture = SQLi_eat(p, "CAPTURE");
    if (!capture && SQLi_need(e, p, "FIELD"))
      goto done;
    char *old = take(e, p), *new = NULL;
    if (!old || SQLi_need(e, p, "TO") || !(new = take(e, p)))
      goto done;
    if (restricted(e, t, old, capture ? "RENAME CAPTURE" : "RENAME FIELD"))
      goto done;
    if (strlen(new) >= 64) {
      SQLi_fail(e, SQL_CONSTRAINT, "identifier too long");
      goto done;
    }
    if (capture) {
      int hit = 0;
      for (int i = 0; i < ns.n; i++)
        for (int k = 0; k < ns.node[i].nc; k++)
          if (!strcmp(ns.node[i].cap[k], old)) {
            strcpy(ns.node[i].cap[k], new);
            hit = 1;
          }
      if (!hit) {
        SQLi_fail(e, SQL_SYNTAX, "unknown capture %s", old);
        goto done;
      }
    } else {
      int id = SQLi_field_id(&ns, old);
      if (id < 0) {
        SQLi_fail(e, SQL_SYNTAX, "unknown field %s", old);
        goto done;
      }
      Node *n = &ns.node[id];
      /* Without MATCH, member filenames derive from the logical name, so the
       * files are renamed in the same journal batch. */
      if (strcmp(n->type, "DIRECTORY") && !n->match[0])
        for (int i = 0; i < t->nr; i++)
          for (int j = 0; j < t->r[i].nm; j++) {
            Member *m = &t->r[i].m[j];
            if (m->field != id)
              continue;
            const char *base = strrchr(m->path, '/') + 1;
            char to[PATH_MAX];
            if (snprintf(to, sizeof(to), "%.*s%s%s", (int)(base - m->path),
                         m->path, new, base + strlen(old)) >= PATH_MAX) {
              SQLi_fail(e, SQL_CONSTRAINT, "renamed path too long");
              goto done;
            }
            char mo[PATH_MAX], mn[PATH_MAX];
            if (SQLi_batch_op(e, &b, 'T', m->path, to) ||
                (m->isnull &&
                 (nullmarker(mo, m->path) || nullmarker(mn, to) ||
                  SQLi_batch_op(e, &b, 'T', mo, mn))))
              goto done;
          }
      strcpy(n->name, new);
    }
  } else if (SQLi_eat(p, "ALTER")) {
    if (SQLi_need(e, p, "FIELD"))
      goto done;
    char *name = take(e, p);
    int id = name ? SQLi_field_id(&ns, name) : -1;
    if (id < 0) {
      SQLi_fail(e, SQL_SYNTAX, "unknown field");
      goto done;
    }
    Node *n = &ns.node[id];
    int leaf = strcmp(n->type, "DIRECTORY") != 0;
    if (SQLi_eat(p, "SET")) {
      if (SQLi_eat(p, "STRICT")) {
        if (!leaf) {
          SQLi_fail(e, SQL_SYNTAX, "STRICT applies to leaf fields");
          goto done;
        }
        n->strict = 1;
        deep = 1; /* existing values must pass the structural validator */
      } else if (SQLi_eat(p, "NOT")) {
        if (SQLi_need(e, p, "NULL"))
          goto done;
        n->notnull = 1;
      } else if (SQLi_eat(p, "DEFAULT")) {
        n->hasdefault = 1;
        n->defnull = SQLi_is(p, "NULL");
        char *v = take(e, p);
        if (!v || strlen(v) >= sizeof(n->def)) {
          SQLi_fail(e, SQL_CONSTRAINT, "invalid DEFAULT");
          goto done;
        }
        strcpy(n->def, n->defnull ? "NULL" : v);
      } else if (SQLi_eat(p, "CARDINALITY")) {
        char *a = NULL;
        if (SQLi_need(e, p, "[") || !(a = take(e, p)) || SQLi_need(e, p, "]"))
          goto done;
        char *x;
        long lo = strtol(a, &x, 10), hi = lo;
        if (x == a || lo < 0) {
          SQLi_fail(e, SQL_SYNTAX, "invalid cardinality");
          goto done;
        }
        if (*x == '-')
          hi = x[1] ? strtol(x + 1, NULL, 10) : -1;
        if (hi >= 0 && hi < lo) {
          SQLi_fail(e, SQL_SYNTAX, "invalid cardinality");
          goto done;
        }
        int was_scalar = n->max == 1;
        n->min = lo;
        n->max = hi;
        /* Implicit names differ for scalars (name[.ext]) and collections
         * (name.N[.ext]); move existing members in the same batch. */
        if (leaf && !n->match[0] && was_scalar != (hi == 1))
          for (int i = 0; i < t->nr; i++) {
            unsigned index = 0;
            for (int j = 0; j < t->r[i].nm; j++) {
              Member *m = &t->r[i].m[j];
              if (m->field != id)
                continue;
              char name2[NAME_MAX + 1], to[PATH_MAX], mo[PATH_MAX],
                  mn[PATH_MAX];
              Node probe = *n;
              probe.compiled = 0;
              probe.format[0] = 0;
              if (SQLi_field_filename(e, &probe, ++index, name2, sizeof(name2)) ||
                  SQLi_joinpath(e, to, t->r[i].path, name2))
                goto done;
              if (index > 1 && hi == 1) {
                SQLi_fail(e, SQL_CONSTRAINT,
                          "record %s has more than one %s member",
                          t->r[i].path, name);
                goto done;
              }
              if (strcmp(to, m->path) &&
                  (SQLi_batch_op(e, &b, 'T', m->path, to) ||
                   (m->isnull &&
                    (nullmarker(mo, m->path) || nullmarker(mn, to) ||
                     SQLi_batch_op(e, &b, 'T', mo, mn)))))
                goto done;
            }
          }
      } else if (SQLi_eat(p, "TYPE")) {
        char *type = take(e, p);
        if (!type || !leaf || strlen(type) >= sizeof(n->type)) {
          SQLi_fail(e, SQL_SYNTAX, "SET TYPE requires a leaf field and type");
          goto done;
        }
        if (restricted(e, t, name, "SET TYPE"))
          goto done;
        if (!n->match[0] &&
            (!strcasecmp(n->type, "JPG") || !strcasecmp(n->type, "MP4") ||
             !strcasecmp(n->type, "SH") || !strcasecmp(type, "JPG") ||
             !strcasecmp(type, "MP4") || !strcasecmp(type, "SH")) &&
            strcasecmp(type, n->type)) {
          SQLi_fail(e, SQL_UNSUPPORTED,
                    "SET TYPE across implicit filename extensions would rename "
                    "files; add an explicit MATCH first");
          goto done;
        }
        snprintf(n->type, sizeof(n->type), "%s", type);
        for (char *c = n->type; *c; c++)
          *c = toupper((unsigned char)*c);
        deep = 1;
      } else {
        SQLi_fail(e, SQL_SYNTAX,
                  "SET NOT NULL | SET DEFAULT v | SET CARDINALITY [m-n] | SET "
                  "TYPE t | SET STRICT");
        goto done;
      }
    } else if (SQLi_eat(p, "DROP")) {
      if (SQLi_eat(p, "STRICT")) {
        n->strict = 0;
      } else if (SQLi_eat(p, "NOT")) {
        if (SQLi_need(e, p, "NULL"))
          goto done;
        n->notnull = 0;
      } else if (SQLi_eat(p, "DEFAULT")) {
        n->hasdefault = n->defnull = 0;
        n->def[0] = 0;
      } else {
        SQLi_fail(e, SQL_SYNTAX, "DROP NOT NULL | DROP DEFAULT | DROP STRICT");
        goto done;
      }
    } else {
      SQLi_fail(e, SQL_SYNTAX, "ALTER FIELD requires SET or DROP");
      goto done;
    }
  } else if (SQLi_eat(p, "SET")) {
    if (SQLi_eat(p, "UNMATCHED")) {
      if (SQLi_eat(p, "IGNORE"))
        ns.unmatched = 1;
      else if (SQLi_need(e, p, "ERROR"))
        goto done;
      else
        ns.unmatched = 0;
    } else if (SQLi_eat(p, "LINKS")) {
      if (SQLi_eat(p, "INTERNAL"))
        ns.links = 1;
      else if (SQLi_need(e, p, "REJECT"))
        goto done;
      else
        ns.links = 0;
    } else {
      SQLi_fail(e, SQL_SYNTAX, "SET UNMATCHED ... | SET LINKS ...");
      goto done;
    }
  } else {
    SQLi_fail(e, SQL_SYNTAX,
              "ALTER TABLE requires RENAME RECORD, ADD FIELD, DROP FIELD, "
              "RENAME FIELD/CAPTURE, ALTER FIELD or SET");
    goto done;
  }
  if (SQLi_eat(p, "VALIDATE")) {
    if (SQLi_need(e, p, "ONLY"))
      goto done;
    validate = 1;
  }
  if (SQLi_end(e, p) || sql_schema_serialize(e, &ns, text, sizeof(text)) ||
      SQLi_schema_text(e, text, &fin))
    goto done;
  /* Value-level revalidation for type/constraint changes on unchanged data. */
  {
    Table probe = {.fd = t->fd};
    probe.schema = fin;
    int bad = SQLi_scan_table(e, &probe, deep);
    for (int i = 0; i < probe.nr; i++) {
      Record *r = &probe.r[i];
      for (int j = 0; j < r->nm; j++) {
        free(r->m[j].path);
        for (int k = 0; k < r->m[j].nc; k++) {
          free(r->m[j].cap[k].name);
          free(r->m[j].cap[k].value);
        }
      }
      for (int k = 0; k < r->nc; k++) {
        free(r->cap[k].name);
        free(r->cap[k].value);
      }
      free(r->m);
      free(r->path);
    }
    free(probe.r);
    /* Structural count errors are expected before ADD backfill/RENAME moves;
     * the batch preflight re-validates the final tree.  Value errors are
     * final. */
    if (bad && (deep || !b.count))
      goto done;
    e->status = 0;
  }
  SQL_Map map = t->map;
  if (map.generation == UINT64_MAX) {
    SQLi_fail(e, SQL_CONSTRAINT, "table generation exhausted");
    goto done;
  }
  map.generation++;
  memset(map.DDL, 0, sizeof(map.DDL));
  strcpy(map.DDL, text);
  if (SQLi_batch_put(e, &b, ".table", &map, sizeof(map)))
    goto done;
  if (validate)
    rc = sql_batch_prepare(e, &b) || sql_preflight(e, &b) ? -1 : 0;
  else
    rc = SQLi_batch_commit(e, &b);
done:
  SQLi_batch_abort(&b);
  SQLi_schema_free(&ns);
  SQLi_schema_free(&fin);
  return rc;
}
