/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
int sql_safe_relative(const char *p) {
  if (!p || !*p || *p == '/' || strlen(p) >= PATH_MAX)
    return 0;
  char *s = strdup(p), *save = NULL;
  if (!s)
    return 0;
  int yes = 1;
  for (char *x = strtok_r(s, "/", &save); x; x = strtok_r(NULL, "/", &save))
    if (!strcmp(x, "..") || !strcmp(x, ".") || strlen(x) > NAME_MAX)
      yes = 0;
  free(s);
  return yes;
}
int sql_parentfd(Env *e, int root, const char *path, char *base) {
  if (!sql_safe_relative(path))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid journal path");
  char *s = strdup(path);
  if (!s)
    return SQLi_fail(e, SQL_IO, "journal path allocation failed");
  char *last = strrchr(s, '/');
  int fd = dup(root);
  if (fd < 0) {
    free(s);
    return SQLi_fail(e, SQL_IO, "journal parent descriptor unavailable");
  }
  if (last) {
    *last = 0;
    strcpy(base, last + 1);
    char *save = NULL;
    for (char *x = strtok_r(s, "/", &save); x; x = strtok_r(NULL, "/", &save)) {
      int n = openat(fd, x, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      close(fd);
      fd = n;
      if (fd < 0) {
        free(s);
        return SQLi_fail(e, SQL_IO, "open journal parent %s: %s", path,
                         strerror(errno));
      }
    }
  } else
    strcpy(base, s);
  free(s);
  return fd;
}
