/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
static int operation(Env *e, Parser *p) {
  return sql_session_cmd(e, "rollback", p);
}
SQL_Status SQL_Rollback(const char *s, const SQL_Options *o, SQL_Result *r) {
  return sql_run("rollback", operation, s, o, r);
}
