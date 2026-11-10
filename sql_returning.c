/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* RETURNING clause for INSERT/UPDATE/DELETE/LINK/UNLINK.  Projections are
 * compiled and validated against the target schema before the mutation
 * commits; values are emitted only after the commit succeeded (post-image
 * for INSERT/UPDATE/LINK/UNLINK, pre-image for DELETE). */
#include "sql_local.h"
int sql_returning_split(Env *e, Parser *p, Parser **out) {
  *out = NULL;
  int depth = 0;
  for (int i = p->p; i < p->n; i++) {
    Tok *t = &p->t[i];
    if (!t->quoted && !strcmp(t->s, "("))
      depth++;
    else if (!t->quoted && !strcmp(t->s, ")"))
      depth--;
    else if (!depth && !t->quoted && !strcasecmp(t->s, "RETURNING")) {
      if (i + 1 >= p->n)
        return SQLi_fail(e, SQL_SYNTAX, "RETURNING requires projections");
      Parser *r = calloc(1, sizeof(*r));
      if (!r)
        return SQLi_fail(e, SQL_IO, "out of memory");
      for (int j = i + 1; j < p->n; j++)
        r->t[r->n++] = p->t[j];
      free(t->s);
      p->n = i;
      *out = r;
      return 0;
    }
  }
  return 0;
}
int sql_returning_prepare(Env *e, Parser *rp, Schema *s, SQL_Returning *r) {
  memset(r, 0, sizeof(*r));
  do {
    if (r->np == NODES)
      return SQLi_fail(e, SQL_CONSTRAINT, "too many RETURNING projections");
    Expr *x = SQLi_expr_parse(e, rp);
    if (!x)
      return -1;
    if (sql_expr_is_star(x)) {
      SQLi_expr_free(x);
      for (int j = 0; j < s->n; j++) {
        Node *n = &s->node[j];
        int k = 0, nk = strcmp(n->type, "DIRECTORY") ? 1 : n->nc;
        for (; k < nk; k++) {
          if (r->np == NODES)
            return SQLi_fail(e, SQL_CONSTRAINT, "RETURNING * exceeds bound");
          r->proj[r->np] =
              sql_expr_ident(e, nk == 1 && strcmp(n->type, "DIRECTORY")
                                    ? n->name
                                    : n->cap[k]);
          if (!r->proj[r->np++])
            return -1;
        }
      }
    } else
      r->proj[r->np++] = x;
  } while (SQLi_eat(rp, ","));
  if (SQLi_end(e, rp))
    return -1;
  r->expand = -1;
  for (int i = 0; i < r->np; i++) {
    int x = sql_expr_expand_field(r->proj[i], s);
    if (x >= 0 && r->expand >= 0 && r->expand != x)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "only one expanded collection per RETURNING");
    if (x >= 0)
      r->expand = x;
  }
  for (int i = 0; i < r->np; i++)
    if (SQLi_expr_validate(e, r->proj[i], s, r->expand >= 0))
      return -1;
  return 0;
}
int sql_returning_emit(Env *e, SQL_Returning *r, Table *t, char *const *paths,
                       int count, FILE *out) {
  int first = 1;
  fputc('[', out);
  for (int i = 0; i < t->nr; i++) {
    Record *rec = &t->r[i];
    int hit = 0;
    for (int j = 0; j < count && !hit; j++)
      hit = !strcmp(paths[j], rec->path);
    if (!hit)
      continue;
    int iterations = r->expand < 0 ? 1 : rec->nm;
    for (int mi = 0; mi < iterations; mi++) {
      Member *m = r->expand < 0 ? NULL : &rec->m[mi];
      if (m && m->field != r->expand)
        continue;
      if (!first)
        fputc(',', out);
      first = 0;
      fputc('[', out);
      for (int j = 0; j < r->np; j++) {
        Value v = {0};
        if (SQLi_expr_eval(e, r->proj[j], t, rec, m, &v))
          return -1;
        if (j)
          fputc(',', out);
        sql_output_value(out, &v);
        SQLi_value_free(&v);
      }
      fputc(']', out);
    }
  }
  fputs("]\n", out);
  return ferror(out) ? SQLi_fail(e, SQL_IO, "write RETURNING rows") : 0;
}
void sql_returning_free(SQL_Returning *r) {
  for (int i = 0; i < r->np; i++)
    SQLi_expr_free(r->proj[i]);
  memset(r, 0, sizeof(*r));
}
