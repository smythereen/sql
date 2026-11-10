/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Direct C++ client, using the same C ABI with deterministic result lifetime.
 */
#include <cstdio>
#include <sql.h>
struct Result {
  SQL_Result value{};
  ~Result() { SQL_Free(&value); }
  Result() = default;
  Result(const Result &) = delete;
  Result &operator=(const Result &) = delete;
};
int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    std::fprintf(stderr, "usage: %s table [select-clauses]\n", argv[0]);
    return 2;
  }
  SQL_Options options{};
  options.cwd = argv[1];
  Result result;
  SQL_Status status =
      SQL_Select(argc == 3 ? argv[2] : "*", &options, &result.value);
  if (status)
    std::fprintf(stderr, "%s\n", result.value.diagnostic);
  else if (result.value.size &&
           std::fwrite(result.value.data, 1, result.value.size, stdout) !=
               result.value.size)
    status = SQL_IO;
  return status;
}
