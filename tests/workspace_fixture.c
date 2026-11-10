/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Scratch-only fault/migration fixture. Never installed. */
#include "sql_local.h"
#include <assert.h>
static uint64_t hash(const void *p, size_t n, uint64_t h) {
  const unsigned char *b = p;
  while (n--) {
    h ^= *b++;
    h *= 1099511628211ULL;
  }
  return h;
}
int main(int ac, char **av) {
  assert(ac >= 3);
  SQL_Result out = {0};
  Env e = {.out = &out};
  assert(getcwd(e.cwd, sizeof(e.cwd)));
  if (!strcmp(av[1], "crossdevice")) {
    assert(ac == 4);
    int root = open(av[2], O_RDONLY | O_DIRECTORY),
        source = open(av[3], O_RDONLY | O_NOFOLLOW);
    assert(root >= 0 && source >= 0);
    Batch batch;
    assert(!SQLi_batch_begin(&e, root, &batch));
    assert(sql_batch_put_file(&e, &batch, "a/blob", source) == -1);
    assert(e.status == SQL_CONSTRAINT);
    struct stat decision;
    assert(fstatat(batch.fd, "COMMIT", &decision, AT_SYMLINK_NOFOLLOW) == -1 &&
           errno == ENOENT);
    SQLi_batch_abort(&batch);
    assert(!sql_safe_relative(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    close(root);
    close(source);
    return 0;
  }
  SQL_Session *s = calloc(1, sizeof(*s));
  assert(s);
  assert(!sql_workspace_open(&e, av[2], s, 1, 0));
  if (!strcmp(av[1], "legacy")) {
    assert(ac == 4);
    size_t prefix = offsetof(SQL_ContextMap, LineageCount),
           slot = ((prefix + 16 + 4095) / 4096) * 4096, total = 4096 + 2 * slot;
    unsigned char *file = calloc(1, total);
    assert(file);
    uint32_t h[6] = {SQL_CTX_FILE_MAGIC, 3, total, 0x01020304,
                     s->map.TraceLevel,  1};
    memcpy(file, h, sizeof(h));
    s->map.LineageVersion = 1;
    s->map.version = 2;
    s->map.bytes = prefix;
    uint64_t seq = 11, crc = hash(&seq, 8, 1469598103934665603ULL);
    crc = hash(&s->map, prefix, crc);
    memcpy(file + 4096, &seq, 8);
    memcpy(file + 4104, &crc, 8);
    memcpy(file + 4112, &s->map, prefix);
    int fd = open(av[3], O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(!sql_write_all(fd, file, total));
    assert(!fsync(fd));
    close(fd);
    free(file);
    if (s->map.State != SQL_CTX_IDLE) {
      char stage[96];
      snprintf(stage, sizeof(stage), ".sql-context.%s.%s", s->map.Nonce,
               s->map.Txid);
      assert(!mkdirat(s->root, stage, 0700));
      int to = openat(s->root, stage, O_RDONLY | O_DIRECTORY),
          from = openat(s->workspace, "tables", O_RDONLY | O_DIRECTORY);
      assert(to >= 0 && from >= 0);
      assert(!sql_tree_copy(&e, from, to, "legacy"));
      assert(!fsync(to));
      close(to);
      close(from);
      assert(!fsync(s->root));
    }
  } else {
    if (!strcmp(av[1], "boot"))
      strcpy(s->map.Boot, "00000000-0000-0000-0000-000000000000");
    else if (!strcmp(av[1], "birth"))
      s->map.Birth++;
    else if (!strcmp(av[1], "lineage"))
      s->map.Lineage[0].Parent++;
    else
      assert(0);
    assert(!sql_ctx_save(&e, s));
  }
  sql_workspace_close(s);
  free(s);
  return 0;
}
