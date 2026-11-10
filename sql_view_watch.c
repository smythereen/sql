/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Explicit foreground filesystem reconciler for one single-source LINKED view.
 * Trigger-unit events are hints; periodic/startup scans recover missed hints.
 */
#include "sql_local.h"
#include <signal.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
typedef struct {
  uint64_t due;
  unsigned debounce, wakeups, overflows;
} ViewWake;
static void changed(s32 tag, char *path, u32 mask, void *arg) {
  (void)tag;
  (void)path;
  ViewWake *w = arg;
  if ((mask & IN_CREATE) && !(mask & IN_ISDIR) &&
      !(mask & ~(IN_CREATE | IN_ISDIR)))
    return;
  w->wakeups++;
  if (mask & IN_Q_OVERFLOW)
    w->overflows++;
  w->due = Trig_Mono() + w->debounce;
}
static int number(Env *e, Parser *p, unsigned max, unsigned *out) {
  char *s = take(e, p), *end;
  if (!s)
    return -1;
  errno = 0;
  unsigned long n = strtoul(s, &end, 10);
  if (!*s || *s == '-' || *end || errno || !n || n > max)
    return SQLi_fail(e, SQL_SYNTAX, "watch duration/debounce out of bounds");
  *out = n;
  return 0;
}
static int reconcile(Env *e, const char *view, int root) {
  Env local = *e;
  SQL_Result result = {0};
  local.out = &result;
  local.status = 0;
  int multi = sql_multiview_kind(&local, root);
  if (multi < 0)
    return local.status;
  if (multi)
    return sql_multiview_reconcile(&local, root);
  local.pinned_view_fd = root + 1;
  Table table = {.fd = -1};
  int rc = sql_relation_open(&local, &table, view);
  SQLi_table_close(&table);
  return rc ? (local.status ? local.status : SQL_IO) : 0;
}
static int identities(Env *e, int root, SQL_ViewMap *initial, int count,
                      const char *view_path) {
  SQL_ViewMap current;
  struct stat st, view_identity;
  if (fstat(root, &view_identity) || lstat(view_path, &st) ||
      !S_ISDIR(st.st_mode) || st.st_dev != view_identity.st_dev ||
      st.st_ino != view_identity.st_ino)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "watched view moved/replaced; no automatic retargeting");
  SQL_ViewMap *maps = calloc(SQL_BRANCH_MAX, sizeof(*maps));
  if (!maps)
    return SQLi_fail(e, SQL_IO, "watch identity allocation");
  int n = sql_multiview_sources(e, root, maps);
  if (!n) {
    if (sql_view_read(e, root, &current)) {
      free(maps);
      return -1;
    }
    maps[0] = current;
    n = 1;
  }
  if (n < 0) {
    free(maps);
    return -1;
  }
  if (n != count) {
    free(maps);
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "watched branch count changed; restart");
  }
  for (int i = 0; i < count; i++) {
    current = maps[i];
    if (current.version != 2 || strcmp(current.Source, initial[i].Source) ||
        current.Device != initial[i].Device ||
        current.Inode != initial[i].Inode) {
      free(maps);
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "watched source definition changed; restart watcher");
    }
    if (lstat(initial[i].Source, &st) || !S_ISDIR(st.st_mode) ||
        st.st_dev != initial[i].Device || st.st_ino != initial[i].Inode) {
      free(maps);
      return SQLi_fail(
          e, SQL_CONSTRAINT,
          "watched source missing/replaced; no automatic retargeting");
    }
  }
  free(maps);
  return 0;
}
int sql_view_watch(Env *e, Parser *p) {
  char *view = take(e, p);
  if (!view)
    return -1;
  unsigned duration = 0, debounce = 100;
  while (p->p < p->n) {
    if (SQLi_eat(p, "DURATION")) {
      if (number(e, p, 3600000, &duration))
        return -1;
    } else if (SQLi_eat(p, "DEBOUNCE")) {
      if (number(e, p, 5000, &debounce))
        return -1;
    } else
      break;
  }
  if (SQLi_end(e, p))
    return -1;
  int root = SQLi_open_dir(e, view), lease = -1, signals = -1, rc = -1,
      masked = 0;
  trig_w_t *watch = NULL;
  sigset_t block, previous;
  SQL_ViewMap *maps = calloc(SQL_BRANCH_MAX, sizeof(*maps));
  int source_fd[SQL_BRANCH_MAX], count = 0;
  for (int i = 0; i < SQL_BRANCH_MAX; i++)
    source_fd[i] = -1;
  char absolute[PATH_MAX], proc[64];
  unsigned refreshes = 0, failures = 0, last_status = 0;
  ViewWake w = {.debounce = debounce};
  if (!maps) {
    SQLi_fail(e, SQL_IO, "watch source list allocation");
    goto done;
  }
  if (root < 0)
    goto done;
  count = sql_multiview_sources(e, root, maps);
  if (count < 0)
    goto done;
  if (!count) {
    if (sql_view_read(e, root, &maps[0]))
      goto done;
    count = 1;
  }
  for (int i = 0; i < count; i++)
    if (maps[i].version != 2) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "WATCH VIEW requires physical LINKED branches");
      goto done;
    }
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", root);
  ssize_t n = readlink(proc, absolute, sizeof(absolute) - 1);
  if (n < 0 || n == sizeof(absolute) - 1)
    goto io;
  absolute[n] = 0;
  for (int i = 0; i < count; i++) {
    size_t len = strlen(maps[i].Source);
    if (!strcmp(absolute, maps[i].Source) ||
        (!strncmp(absolute, maps[i].Source, len) &&
         (len == 1 || absolute[len] == '/'))) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "watched view must be outside every source tree");
      goto done;
    }
    if (len >= TRIG_PATH_LEN) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "source watch path exceeds trigger bound 255");
      goto done;
    }
  }
  if (identities(e, root, maps, count, absolute))
    goto done;
  lease = openat(root, ".sql-view-watch",
                 O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
  struct stat owned;
  if (lease < 0)
    goto io;
  if (fstat(lease, &owned) || !S_ISREG(owned.st_mode) ||
      owned.st_uid != getuid() || (owned.st_mode & 0077) || owned.st_size ||
      flock(lease, LOCK_EX | LOCK_NB)) {
    SQLi_fail(e, SQL_CONSTRAINT, "view already watched or invalid watch lease");
    goto done;
  }
  sigemptyset(&block);
  sigaddset(&block, SIGINT);
  sigaddset(&block, SIGTERM);
  if (pthread_sigmask(SIG_BLOCK, &block, &previous))
    goto io;
  masked = 1;
  signals = signalfd(-1, &block, SFD_CLOEXEC | SFD_NONBLOCK);
  if (signals < 0)
    goto io;
  watch = Trig_Open();
  if (!watch)
    goto io;
  for (int i = 0; i < count; i++) {
    int duplicate = 0;
    for (int j = 0; j < i; j++)
      if (maps[i].Device == maps[j].Device && maps[i].Inode == maps[j].Inode)
        duplicate = 1;
    if (duplicate)
      continue;
    source_fd[i] = SQLi_open_dir(e, maps[i].Source);
    struct stat source_identity;
    if (source_fd[i] < 0 || fstat(source_fd[i], &source_identity) ||
        source_identity.st_dev != maps[i].Device ||
        source_identity.st_ino != maps[i].Inode) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "source identity changed before registration");
      goto done;
    }
    char anchor[64];
    snprintf(anchor, sizeof(anchor), "/proc/self/fd/%d", source_fd[i]);
    if (Trig_Add(watch, anchor,
                 IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO | IN_MOVED_FROM |
                     IN_DELETE | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF,
                 TRIG_F_RECURSIVE, 0, i + 1) < 0)
      goto io;
  }
  /* Watch first, then rescan: changes racing startup remain queued. */
  unsigned status = reconcile(e, absolute, root);
  if (status) {
    failures++;
    last_status = status;
    fprintf(stderr,
            "sql watch VIEW initial refresh deferred (status %u); retrying\n",
            status);
  } else
    refreshes++;
  fprintf(stderr, "sql watch VIEW ready (filesystem refresh active)\n");
  fflush(stderr);
  uint64_t start = Trig_Mono(), until = duration ? start + duration : 0,
           next_scan = start + 1000;
  for (;;) {
    struct signalfd_siginfo signal_info;
    if (read(signals, &signal_info, sizeof(signal_info)) == sizeof(signal_info))
      break;
    uint64_t now = Trig_Mono();
    if (until && now >= until)
      break;
    if ((w.due && now >= w.due) || now >= next_scan) {
      if (identities(e, root, maps, count, absolute))
        goto done;
      status = reconcile(e, absolute, root);
      if (status != last_status) {
        fprintf(stderr, "sql watch VIEW refresh %s (status %u)\n",
                status ? "deferred; retrying" : "recovered", status);
        fflush(stderr);
      }
      if (status) {
        failures++;
        last_status = status;
      } else {
        refreshes++;
        last_status = 0;
      }
      w.due = 0;
      next_scan = Trig_Mono() + 1000;
    }
    if (Trig_Poll(watch, 50, changed, &w) < 0 && errno != EINTR)
      goto io;
  }
  fprintf(e->stream,
          "{\"refreshes\":%u,\"failures\":%u,\"last_status\":%u,\"wakeups\":%u,"
          "\"overflows\":%u}\n",
          refreshes, failures, last_status, w.wakeups, w.overflows);
  rc = 0;
  goto done;
io:
  if (!e->status)
    SQLi_fail(e, SQL_IO, "filesystem view watcher: %s", strerror(errno));
done:
  if (watch)
    Trig_Close(watch);
  if (signals >= 0)
    close(signals);
  if (masked)
    pthread_sigmask(SIG_SETMASK, &previous, NULL);
  for (int i = 0; i < SQL_BRANCH_MAX; i++)
    if (source_fd[i] >= 0)
      close(source_fd[i]);
  free(maps);
  if (lease >= 0)
    close(lease);
  if (root >= 0)
    close(root);
  return rc;
}
