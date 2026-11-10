/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* A real libsql transaction client: provision the context separately. */
#include <sql.h>
#include <stdio.h>
#include <string.h>
static int checked(SQL_Status status, SQL_Result *result) {
  if (status)
    fprintf(stderr, "%d: %s\n", status, result->diagnostic);
  SQL_Free(result);
  return status;
}
int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s table context new-title\n", argv[0]);
    return 2;
  }
  SQL_Options options = {0};
  options.cwd = argv[1];
  options.context = argv[2];
  SQL_Binding binding = {"title", SQL_BIND_TEXT, argv[3], strlen(argv[3])};
  options.bindings = &binding;
  options.binding_count = 1;
  SQL_Result result;
  int status = checked(SQL_Begin("", &options, &result), &result);
  if (status)
    return status;
  status = checked(
      SQL_Update("SET title=:title ALL RECORDS", &options, &result), &result);
  if (status) {
    checked(SQL_Rollback("", &options, &result), &result);
    return status;
  }
  status = SQL_Commit("RETURNING TRANSACTION", &options, &result);
  if (!status && fwrite(result.data, 1, result.size, stdout) != result.size)
    status = SQL_IO;
  /* A failed or uncertain COMMIT must NOT be treated as a rollback. */
  return checked((SQL_Status)status, &result);
}
