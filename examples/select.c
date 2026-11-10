/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Direct C library client: no command execution. */
#include <sql.h>
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s table [select-clauses]\n", argv[0]);
    return 2;
  }
  SQL_Options options = {0};
  SQL_Result result;
  options.cwd = argv[1];
  SQL_Status status = SQL_Select(argc == 3 ? argv[2] : "*", &options, &result);
  if (status)
    fprintf(stderr, "%s\n", result.diagnostic);
  else if (result.size &&
           fwrite(result.data, 1, result.size, stdout) != result.size)
    status = SQL_IO;
  SQL_Free(&result);
  return status;
}
