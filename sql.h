/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef SQL_H
#define SQL_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define SQL_VERSION 1
#define SQL_TRACE 0x01000000u
/* Result owns bytes (not necessarily text); free with SQL_Free. No stdout in
 * APIs. Calls serialize legacy map/mio/sys globals. Do not call from signal
 * handlers. cwd=NULL means invocation cwd. Statement is SQL, never a shell
 * command. */
typedef enum {
  SQL_OK = 0,
  SQL_SYNTAX = 2,
  SQL_IO = 3,
  SQL_CONSTRAINT = 4,
  SQL_NO_MATCH = 5,
  SQL_COMMITTED_PENDING = 6,
  SQL_UNSUPPORTED = 7
} SQL_Status;
typedef struct {
  unsigned char *data;
  size_t size;
  char diagnostic[1024];
} SQL_Result;
typedef enum {
  SQL_BIND_TEXT,
  SQL_BIND_INT64,
  SQL_BIND_UINT64,
  SQL_BIND_BOOL,
  SQL_BIND_NULL
} SQL_BindType;
typedef struct {
  const char *name;
  SQL_BindType type;
  const void *data;
  size_t size;
} SQL_Binding;
typedef struct {
  const char *cwd;
  unsigned lock_timeout_ms;
  const SQL_Binding *bindings;
  size_t binding_count;
  const char *context; /* Explicit checked session; never an implicit table. */
} SQL_Options;
void SQL_Free(SQL_Result *result);
SQL_Status SQL_Execute(const char *command, const char *statement,
                       const SQL_Options *options, SQL_Result *result);
SQL_Status SQL_Create(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Define(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Describe(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Show(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Select(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Insert(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Update(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Delete(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Link(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Unlink(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Alter(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Drop(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Begin(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Commit(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Rollback(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Context(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Trigger(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Watch(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Check(const char *, const SQL_Options *, SQL_Result *);
SQL_Status SQL_Recover(const char *, const SQL_Options *, SQL_Result *);
int SQL_CLI(const char *, int, char **);
int SQL_MemCLI(const char *, int, char **);
#ifdef __cplusplus
}
#endif
#endif
