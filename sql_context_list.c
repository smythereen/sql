/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
int sql_context_list(Env *e, Parser *p) {
  if (SQLi_need(e, p, "ON"))
    return -1;
  char *path = take(e, p);
  if (!path || SQLi_end(e, p))
    return -1;
  int root = SQLi_open_dir(e, path);
  if (root < 0)
    return -1;
  if (sql_root_check(e, root)) {
    close(root);
    return -1;
  }
  int registry = sql_registry(e, root, 0);
  if (registry < 0) {
    close(root);
    return -1;
  }
  DIR *d = fdopendir(openat(registry, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!d) {
    close(registry);
    close(root);
    return SQLi_fail(e, SQL_IO, "scan workspace registry");
  }
  struct dirent *de;
  int rc = 0;
  while ((de = readdir(d))) {
    if (de->d_name[0] == '.')
      continue;
    char rel[NAME_MAX + 32], handle[PATH_MAX];
    snprintf(rel, sizeof(rel), ".context/%s", de->d_name);
    if (SQLi_joinpath(e, handle, path, rel)) {
      rc = -1;
      break;
    }
    SQL_Session *s = malloc(sizeof(*s));
    if (!s) {
      rc = SQLi_fail(e, SQL_IO, "out of memory");
      break;
    }
    Env probe = *e;
    SQL_Result ignored = {0};
    probe.out = &ignored;
    probe.status = 0;
    if (sql_workspace_open(&probe, handle, s, 1, 1)) {
      int busy = errno == EWOULDBLOCK || errno == EAGAIN;
      sql_workspace_close(s);
      free(s);
      if (!busy) {
        rc = SQLi_fail(e, probe.status, "%s", ignored.diagnostic);
        break;
      }
      fputs("{\"context\":", e->stream);
      SQLi_json(e->stream, (unsigned char *)handle, strlen(handle));
      fputs(",\"busy\":true}\n", e->stream);
      continue;
    }
    int state = sql_lineage_state(&s->map);
    const char *labels[] = {"live", "changed", "dead-or-reused", "prior-boot",
                            "legacy-unverified"};
    fputs("{\"context\":", e->stream);
    SQLi_json(e->stream, (unsigned char *)s->path, strlen(s->path));
    fprintf(
        e->stream,
        ",\"busy\":false,\"owner_pid\":%u,\"owner_uid\":%u,\"owner_birth\":%"
        "llu,\"owner_live\":%s,\"inheritance_valid\":%s,\"lineage_state\":\"%"
        "s\",\"lineage_count\":%u,\"state\":%u,\"outcome\":%u,\"participants\":"
        "%u,\"command_sequence\":%llu,\"command_phase\":%u,\"boot\":",
        s->map.PID, s->map.UID, (unsigned long long)s->map.Birth,
        state < 2 ? "true" : "false", state == 0 ? "true" : "false",
        labels[state], s->map.LineageCount, s->map.State, s->map.Outcome,
        s->map.Count, (unsigned long long)s->map.Command.Sequence,
        s->map.Command.Phase);
    SQLi_json(e->stream, (unsigned char *)s->map.Boot, strlen(s->map.Boot));
    fputs(",\"transaction\":", e->stream);
    SQLi_json(e->stream, (unsigned char *)s->map.Txid, strlen(s->map.Txid));
    fputs("}\n", e->stream);
    sql_workspace_close(s);
    free(s);
  }
  closedir(d);
  close(registry);
  close(root);
  return rc;
}
