/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Linked-view metadata snapshots only: payload bytes remain in the source.
 * Caller holds exclusive view and shared source directory locks. */
#include "sql_local.h"
typedef struct {
  uint32_t magic, version, uid, reserved;
  uint64_t view_device, view_inode, source_device, source_inode, generation,
      query_hash, members_hash;
} LinkedStamp;
static uint64_t hash_text(uint64_t h, const char *s) {
  do {
    h ^= (unsigned char)*s;
    h *= 1099511628211ULL;
  } while (*s++);
  return h;
}
static int stamp_write(Env *e, int dir, const char *name,
                       const LinkedStamp *s) {
  int fd = openat(dir, name,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "create linked snapshot metadata");
  int bad = sql_write_all(fd, s, sizeof(*s)) || fsync(fd);
  close(fd);
  return bad ? SQLi_fail(e, SQL_IO, "sync linked snapshot metadata") : 0;
}
static int stamp_read(Env *e, int dir, const char *name, LinkedStamp *s) {
  struct stat st;
  int fd = sql_regular_open(e, dir, name, 0, &st);
  if (fd < 0)
    return -1;
  int bad = st.st_uid != getuid() || (st.st_mode & 0077) ||
            st.st_size != sizeof(*s) || sql_read_all(fd, s, sizeof(*s));
  close(fd);
  if (bad || s->magic != 0x314b4e4c || s->version != 1 || s->uid != getuid() ||
      s->reserved)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid/private linked ownership metadata");
  return 0;
}
static int directory(Env *e, int root, const char *path) {
  if (!sql_safe_relative(path))
    return SQLi_fail(e, SQL_CONSTRAINT, "unsafe linked record path");
  char *copy = strdup(path);
  if (!copy)
    return SQLi_fail(e, SQL_IO, "linked path allocation");
  int fd = dup(root);
  char *save = NULL;
  for (char *part = strtok_r(copy, "/", &save); part;
       part = strtok_r(NULL, "/", &save)) {
    if ((mkdirat(fd, part, 0700) && errno != EEXIST) || fsync(fd)) {
      close(fd);
      free(copy);
      return SQLi_fail(e, SQL_IO, "create/sync linked directory");
    }
    int child =
        openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(fd);
    fd = child;
    if (fd < 0) {
      free(copy);
      return SQLi_fail(e, SQL_CONSTRAINT, "linked path collision");
    }
  }
  free(copy);
  return fd;
}
static Member *physical_member(Record *row, int field) {
  for (int i = 0; i < row->nm; i++)
    if (row->m[i].field == field)
      return &row->m[i];
  return NULL;
}
int sql_linked_refresh(Env *e, int view, Table *source, Record **rows,
                       size_t count, const int *fields, int np,
                       char names[NODES][64], const char *query) {
  struct stat vst, sst;
  if (fstat(view, &vst) || fstat(source->fd, &sst))
    return SQLi_fail(e, SQL_IO, "linked source/view identity");
  SQL_ViewMap definition;
  if (sql_view_read(e, view, &definition))
    return -1;
  if (definition.version != 2 || definition.Device != sst.st_dev ||
      definition.Inode != sst.st_ino || strcmp(definition.Source, source->path))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "linked source identity changed before publication");
  LinkedStamp owner = {.magic = 0x314b4e4c,
                       .version = 1,
                       .uid = getuid(),
                       .view_device = vst.st_dev,
                       .view_inode = vst.st_ino};
  int meta = openat(view, ".linked",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
      generation = -1, rc = -1;
  if (meta < 0 && errno == ENOENT) {
    char id[33], temporary[80];
    if (sql_uuid(e, id))
      return -1;
    snprintf(temporary, sizeof(temporary), ".sql-linked-init.%s", id);
    if (mkdirat(view, temporary, 0700))
      return SQLi_fail(e, SQL_IO, "initialize linked namespace");
    meta = openat(view, temporary,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (meta < 0 || stamp_write(e, meta, "owner", &owner) || fsync(meta) ||
        renameat2(view, temporary, view, ".linked", RENAME_NOREPLACE) ||
        fsync(view))
      goto io;
  }
  if (meta < 0)
    goto io;
  LinkedStamp saved;
  if (stamp_read(e, meta, "owner", &saved))
    goto done;
  if (memcmp(&saved, &owner, sizeof(owner))) {
    SQLi_fail(e, SQL_CONSTRAINT, "foreign linked namespace; untouched");
    goto done;
  }
  LinkedStamp desired = owner;
  desired.source_device = sst.st_dev;
  desired.source_inode = sst.st_ino;
  desired.generation = source->map.generation;
  desired.query_hash = hash_text(1469598103934665603ULL, query);
  desired.members_hash = 1469598103934665603ULL;
  for (size_t i = 0; i < count; i++) {
    if (!rows[i]->path || !sql_safe_relative(rows[i]->path)) {
      SQLi_fail(e, SQL_CONSTRAINT, "invalid linked record path");
      goto done;
    }
    desired.members_hash = hash_text(desired.members_hash, rows[i]->path);
    for (int j = 0; j < np; j++) {
      Member *m = physical_member(rows[i], fields[j]);
      desired.members_hash = hash_text(desired.members_hash, names[j]);
      desired.members_hash = hash_text(desired.members_hash, m ? m->path : "");
    }
  }
  char previous[96] = {0}, old_meta[80];
  struct stat previous_st;
  int exists = !fstatat(view, "records", &previous_st, AT_SYMLINK_NOFOLLOW);
  if (!exists && errno != ENOENT)
    goto io;
  if (exists) {
    ssize_t n = readlinkat(view, "records", previous, sizeof(previous) - 1);
    if (!S_ISLNK(previous_st.st_mode) || n != 40 ||
        strncmp(previous, ".linked/", 8)) {
      SQLi_fail(e, SQL_CONSTRAINT, "unmanaged records entry; preserved");
      goto done;
    }
    previous[n] = 0;
    for (int i = 8; i < 40; i++)
      if (!isxdigit((unsigned char)previous[i])) {
        SQLi_fail(e, SQL_CONSTRAINT, "foreign records link; preserved");
        goto done;
      }
    snprintf(old_meta, sizeof(old_meta), "%.32s.meta", previous + 8);
    if (stamp_read(e, meta, old_meta, &saved))
      goto done;
    if (saved.view_device != owner.view_device ||
        saved.view_inode != owner.view_inode) {
      SQLi_fail(e, SQL_CONSTRAINT, "foreign records snapshot; preserved");
      goto done;
    }
    int check = openat(meta, previous + 8,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (check < 0)
      goto io;
    close(check);
    if (!memcmp(&saved, &desired, sizeof(saved))) {
      rc = 0;
      goto done;
    }
  }
  char id[33], metadata[80], target[80], temporary[80];
  if (sql_uuid(e, id))
    goto done;
  if (mkdirat(meta, id, 0700))
    goto io;
  generation =
      openat(meta, id, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (generation < 0)
    goto io;
  for (size_t i = 0; i < count; i++) {
    int row = directory(e, generation, rows[i]->path);
    if (row < 0)
      goto done;
    for (int j = 0; j < np; j++) {
      if (!SQLi_component(names[j])) {
        close(row);
        SQLi_fail(e, SQL_CONSTRAINT, "unsafe linked projection alias");
        goto done;
      }
      Member *m = physical_member(rows[i], fields[j]);
      if (!m)
        continue;
      char absolute[PATH_MAX];
      if (!sql_safe_relative(m->path) ||
          SQLi_joinpath(e, absolute, source->path, m->path) ||
          symlinkat(absolute, row, names[j])) {
        close(row);
        if (!e->status)
          SQLi_fail(e, SQL_CONSTRAINT, "linked projection/path collision");
        goto done;
      }
    }
    int bad = fsync(row);
    close(row);
    if (bad)
      goto io;
  }
  snprintf(metadata, sizeof(metadata), "%s.meta", id);
  if (fsync(generation) || stamp_write(e, meta, metadata, &desired) ||
      fsync(meta))
    goto io;
  snprintf(target, sizeof(target), ".linked/%s", id);
  snprintf(temporary, sizeof(temporary), ".sql-linked-link.%s", id);
  if (symlinkat(target, view, temporary) || fsync(view))
    goto io;
  /* Old generations are retained for raw readers; see sql_linked_prune. */
  if (!exists) {
    if (renameat2(view, temporary, view, "records", RENAME_NOREPLACE))
      goto io;
  } else {
    if (renameat2(view, temporary, view, "records", RENAME_EXCHANGE))
      goto io;
    struct stat replaced;
    int same = !fstatat(view, temporary, &replaced, AT_SYMLINK_NOFOLLOW) &&
               replaced.st_dev == previous_st.st_dev &&
               replaced.st_ino == previous_st.st_ino;
    if (!same) {
      if (renameat2(view, temporary, view, "records", RENAME_EXCHANGE))
        goto io;
      SQLi_fail(e, SQL_CONSTRAINT,
                "records changed outside SQL locks; preserved");
      goto done;
    }
    if (unlinkat(view, temporary, 0))
      goto io;
  }
  if (fsync(view))
    goto io;
  { /* bounded automatic GC: 8 previous generations, 60 s grace */
    unsigned removed, kept;
    Env probe = *e;
    SQL_Result ignored = {0};
    probe.out = &ignored;
    probe.status = 0;
    sql_linked_prune(&probe, view, 8, 60, &removed, &kept);
  }
  rc = 0;
  goto done;
io:
  if (!e->status)
    SQLi_fail(e, SQL_IO, "linked snapshot publication: %s", strerror(errno));
done:
  if (generation >= 0)
    close(generation);
  if (meta >= 0)
    close(meta);
  return rc;
}
/* Generation GC. Old generations stay readable for raw readers that resolved
 * records/ before a republish; they are removed only when older than the
 * current generation, beyond the newest `keep` previous ones, and (for the
 * automatic pass) older than a grace period. Callers hold the exclusive view
 * lock, which also serializes publication. */
static int remove_tree(int dir, const char *name, int depth) {
  if (depth > 64)
    return -1;
  int fd = openat(dir, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return errno == ENOENT ? 0 : -1;
  DIR *d = fdopendir(fd);
  if (!d) {
    close(fd);
    return -1;
  }
  struct dirent *de;
  int rc = 0;
  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;
    struct stat st;
    if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW))
      continue;
    if (S_ISDIR(st.st_mode))
      rc |= remove_tree(fd, de->d_name, depth + 1);
    else if (S_ISLNK(st.st_mode))
      rc |= unlinkat(fd, de->d_name, 0) ? -1 : 0;
    else
      rc = -1; /* generations hold only directories and symlinks */
  }
  closedir(d);
  if (!rc && unlinkat(dir, name, AT_REMOVEDIR))
    rc = -1;
  return rc;
}
/* 1 when the tree holds only directories and symlinks (engine-made). */
static int managed_only(int dir, const char *name, int depth) {
  if (depth > 64)
    return 0;
  int fd = openat(dir, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return 0;
  DIR *d = fdopendir(fd);
  if (!d) {
    close(fd);
    return 0;
  }
  struct dirent *de;
  int ok = 1;
  while (ok && (de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;
    struct stat st;
    if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW))
      ok = 0;
    else if (S_ISDIR(st.st_mode))
      ok = managed_only(fd, de->d_name, depth + 1);
    else if (!S_ISLNK(st.st_mode))
      ok = 0;
  }
  closedir(d);
  return ok;
}
typedef struct {
  char id[33];
  struct timespec when;
} Gen;
static int newer(const void *a, const void *b) {
  const Gen *x = a, *y = b;
  if (x->when.tv_sec != y->when.tv_sec)
    return x->when.tv_sec > y->when.tv_sec ? -1 : 1;
  if (x->when.tv_nsec != y->when.tv_nsec)
    return x->when.tv_nsec > y->when.tv_nsec ? -1 : 1;
  return strcmp(x->id, y->id);
}
int sql_linked_prune(Env *e, int view, unsigned keep, unsigned grace,
                     unsigned *removed, unsigned *kept) {
  *removed = *kept = 0;
  int meta = openat(view, ".linked",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (meta < 0)
    return errno == ENOENT ? 0 : SQLi_fail(e, SQL_IO, "open linked namespace");
  char current[96] = {0};
  ssize_t n = readlinkat(view, "records", current, sizeof(current) - 1);
  if (n != 40 || strncmp(current, ".linked/", 8)) {
    close(meta);
    return n < 0 && errno == ENOENT
               ? 0
               : SQLi_fail(e, SQL_CONSTRAINT, "unmanaged records entry");
  }
  current[n] = 0;
  struct stat cur;
  char cur_meta[48];
  snprintf(cur_meta, sizeof(cur_meta), "%.32s.meta", current + 8);
  if (fstatat(meta, cur_meta, &cur, AT_SYMLINK_NOFOLLOW)) {
    close(meta);
    return SQLi_fail(e, SQL_IO, "current linked generation metadata");
  }
  DIR *d = fdopendir(dup(meta));
  Gen *list = NULL;
  size_t count = 0, cap = 0;
  struct dirent *de;
  int rc = 0;
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  while (d && (de = readdir(d))) {
    if (strlen(de->d_name) != 32 ||
        strspn(de->d_name, "0123456789abcdef") != 32 ||
        !strcmp(de->d_name, current + 8))
      continue;
    char m[48];
    struct stat st, ms;
    snprintf(m, sizeof(m), "%.32s.meta", de->d_name);
    if (fstatat(meta, de->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
        !S_ISDIR(st.st_mode))
      continue;
    /* No metadata: an interrupted publication; age decides. */
    if (fstatat(meta, m, &ms, AT_SYMLINK_NOFOLLOW))
      ms = st;
    if (ms.st_mtim.tv_sec > cur.st_mtim.tv_sec ||
        (ms.st_mtim.tv_sec == cur.st_mtim.tv_sec &&
         ms.st_mtim.tv_nsec > cur.st_mtim.tv_nsec))
      continue; /* never newer than the published generation */
    if (count == cap) {
      cap = cap ? cap * 2 : 16;
      Gen *g = realloc(list, cap * sizeof(*g));
      if (!g) {
        rc = SQLi_fail(e, SQL_IO, "linked GC allocation");
        break;
      }
      list = g;
    }
    memcpy(list[count].id, de->d_name, 33);
    list[count++].when = ms.st_mtim;
  }
  if (d)
    closedir(d);
  if (!rc) {
    if (count)
      qsort(list, count, sizeof(*list), newer);
    for (size_t i = 0; i < count; i++) {
      if (i < keep || now.tv_sec - list[i].when.tv_sec < (time_t)grace ||
          !managed_only(meta, list[i].id, 0)) { /* unmanaged content kept */
        (*kept)++;
        continue;
      }
      char m[48];
      snprintf(m, sizeof(m), "%s.meta", list[i].id);
      if (remove_tree(meta, list[i].id, 0) ||
          (unlinkat(meta, m, 0) && errno != ENOENT)) {
        rc = SQLi_fail(e, SQL_IO, "remove linked generation %s", list[i].id);
        break;
      }
      (*removed)++;
    }
    if (!rc && *removed && fsync(meta))
      rc = SQLi_fail(e, SQL_IO, "sync linked namespace");
  }
  free(list);
  close(meta);
  return rc;
}
