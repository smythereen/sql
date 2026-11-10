/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
#include <assert.h>
#include <poll.h>
int main(int ac, char **av) {
  assert(ac == 2);
  Env e = {0};
  SQL_Result result = {0};
  e.out = &result;
  assert(getcwd(e.cwd, sizeof(e.cwd)));
  assert(!sql_session_load(&e, av[1], NULL, 1));
  u32 *word = TracePointer;
  assert(word == e.session->trace.word);
  printf("READY %ld\n", (long)getpid());
  fflush(stdout);
  struct pollfd fd = {.fd = STDIN_FILENO, .events = POLLIN};
  assert(poll(&fd, 1, 15000) > 0);
  char c;
  assert(read(STDIN_FILENO, &c, 1) == 1);
  assert(TracePointer == word);
  volatile u32 value = *word;
  (void)value;
  sql_session_close(&e);
  puts("HOLDER_CLOSED");
  return 0;
}
