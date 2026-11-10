/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
/* map's cache is keyed by inode, has no reference counts and force-unmaps a
 * cached entry on a protection change. This adapter protects active SQL scopes
 * without changing the map unit or hiding copied masks behind TracePointer. */
typedef struct {
  void *address;
  dev_t device;
  ino_t inode;
  size_t size;
  int prot, refs;
} Mapping;
static Mapping mappings[128];
void *sql_mapping(Env *e, int fd, size_t size, int prot) {
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != (off_t)size) {
    SQLi_fail(e, SQL_CONSTRAINT, "mapped file identity/size/type changed");
    return NULL;
  }
  int slot = -1;
  for (int i = 0; i < 128; i++) {
    Mapping *m = &mappings[i];
    if (!m->refs) {
      if (slot < 0)
        slot = i;
      continue;
    }
    if (m->device == st.st_dev && m->inode == st.st_ino) {
      if (m->size != size || m->prot != prot) {
        SQLi_fail(e, SQL_IO,
                  "incompatible live mapping; caller scope preserved");
        return NULL;
      }
      m->refs++;
      return m->address;
    }
  }
  if (slot < 0) {
    SQLi_fail(e, SQL_IO, "SQL mapping scope limit");
    return NULL;
  }
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
  void *p = Map(proc, 0, size, prot);
  if (!p) {
    SQLi_fail(e, SQL_IO, "map-unit mapping failed");
    return NULL;
  }
  mappings[slot] = (Mapping){.address = p,
                             .device = st.st_dev,
                             .inode = st.st_ino,
                             .size = size,
                             .prot = prot,
                             .refs = 1};
  return p;
}
void sql_unmapping(void *p) {
  if (!p)
    return;
  for (int i = 0; i < 128; i++)
    if (mappings[i].refs && mappings[i].address == p) {
      if (--mappings[i].refs == 0) {
        UnmapAddress(p, 1);
        memset(&mappings[i], 0, sizeof(mappings[i]));
      }
      return;
    }
}
int sql_trace_map(Env *e, int fd, size_t size, size_t offset, int prot,
                  SQL_TraceScope *scope) {
  if (!scope || scope->address || size < sizeof(u32) ||
      offset > size - sizeof(u32) || offset % _Alignof(u32))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid Trace scope binding");
  void *p = sql_mapping(e, fd, size, prot);
  if (!p)
    return -1;
  *scope = (SQL_TraceScope){.address = p,
                            .size = size,
                            .previous = TracePointer,
                            .word = (u32 *)((char *)p + offset)};
  TracePointer = scope->word;
  return 0;
}
void sql_trace_unmap(SQL_TraceScope *scope) {
  if (!scope->address)
    return; /* Restore before unmapping: map's Unmap also inspects TracePointer.
             */
  TracePointer = scope->previous;
  sql_unmapping(scope->address);
  memset(scope, 0, sizeof(*scope));
}
int sql_trace_store(Env *e, int fd, size_t size, size_t offset,
                    uint32_t value) {
  if (size < sizeof(u32) || offset > size - sizeof(u32) ||
      offset % _Alignof(u32))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid Trace variable bounds");
  void *p = sql_mapping(e, fd, size, PROT_WRITE);
  if (!p)
    return -1;
  u32 *word = (u32 *)((char *)p + offset);
  __atomic_store_n(word, value, __ATOMIC_RELEASE);
  UpdateMap(p, size);
  int rc = msync(p, size, MS_SYNC) || fsync(fd);
  sql_unmapping(p);
  return rc ? SQLi_fail(e, SQL_IO,
                        "live Trace variable synchronization failed; value may "
                        "be visible")
            : 0;
}
int sql_trace_object_set(Env *e, const char *path, int view, uint32_t value) {
  int root = SQLi_open_dir(e, path);
  if (root < 0)
    return -1;
  int rc = -1;
  if (SQLi_lockdir(e, root, 0))
    goto done;
  SQL_Map table;
  SQL_ViewMap map;
  if (view ? sql_view_read(e, root, &map)
           : SQLi_map_read(e, root, ".table", &table))
    goto done;
  int fd = sql_regular_open(e, root, view ? ".view" : ".table", 1, NULL);
  if (fd < 0)
    goto done;
  if (SQLi_lockdir(e, fd, 1)) {
    close(fd);
    goto done;
  }
  rc = sql_trace_store(e, fd, view ? sizeof(map) : sizeof(table),
                       view ? offsetof(SQL_ViewMap, TraceLevel)
                            : offsetof(SQL_Map, TraceLevel),
                       value);
  close(fd);
done:
  close(root);
  return rc;
}
