/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
SQL_Status SQL_Execute(const char *cmd, const char *s, const SQL_Options *o,
                       SQL_Result *r) {
  if (cmd && !strncasecmp(cmd, "sql_", 4))
    cmd += 4;
  if (cmd && !strcasecmp(cmd, "create"))
    return SQL_Create(s, o, r);
  if (cmd && !strcasecmp(cmd, "define"))
    return SQL_Define(s, o, r);
  if (cmd && !strcasecmp(cmd, "describe"))
    return SQL_Describe(s, o, r);
  if (cmd && !strcasecmp(cmd, "show"))
    return SQL_Show(s, o, r);
  if (cmd && !strcasecmp(cmd, "select"))
    return SQL_Select(s, o, r);
  if (cmd && !strcasecmp(cmd, "insert"))
    return SQL_Insert(s, o, r);
  if (cmd && !strcasecmp(cmd, "update"))
    return SQL_Update(s, o, r);
  if (cmd && !strcasecmp(cmd, "delete"))
    return SQL_Delete(s, o, r);
  if (cmd && !strcasecmp(cmd, "link"))
    return SQL_Link(s, o, r);
  if (cmd && !strcasecmp(cmd, "unlink"))
    return SQL_Unlink(s, o, r);
  if (cmd && !strcasecmp(cmd, "alter"))
    return SQL_Alter(s, o, r);
  if (cmd && !strcasecmp(cmd, "drop"))
    return SQL_Drop(s, o, r);
  if (cmd && !strcasecmp(cmd, "begin"))
    return SQL_Begin(s, o, r);
  if (cmd && !strcasecmp(cmd, "commit"))
    return SQL_Commit(s, o, r);
  if (cmd && !strcasecmp(cmd, "rollback"))
    return SQL_Rollback(s, o, r);
  if (cmd && !strcasecmp(cmd, "context"))
    return SQL_Context(s, o, r);
  if (cmd && !strcasecmp(cmd, "trigger"))
    return SQL_Trigger(s, o, r);
  if (cmd && !strcasecmp(cmd, "watch"))
    return SQL_Watch(s, o, r);
  if (cmd && !strcasecmp(cmd, "check"))
    return SQL_Check(s, o, r);
  if (cmd && !strcasecmp(cmd, "recover"))
    return SQL_Recover(s, o, r);
  if (r) {
    memset(r, 0, sizeof(*r));
    snprintf(r->diagnostic, sizeof(r->diagnostic), "unknown command");
  }
  return SQL_SYNTAX;
}
