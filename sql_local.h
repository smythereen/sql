/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef SQL_LOCAL_H
#define SQL_LOCAL_H
#define _GNU_SOURCE
#include "sql.h"
#include <common.h>
#include <dirent.h>
#include <errno.h>
#include <far.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <map.h>
#include <mem_io.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <trigger.h>
#include <unistd.h>
#define NODES 64
#define CAPMAX 8
#define DDL_SIZE 16384
#define TOKMAX 8192
#define VALMAX (64u * 1024u * 1024u)
#define MAGIC 0x314c5153u
/* Fixed, pointer-free native endian v1 format; exact size/endian checked.
 * Full schema text is persisted, runtime regexes/descriptors are rebuilt. */
typedef struct {
  uint32_t magic, version, bytes, endian, TraceLevel, kind;
  uint64_t generation;
  char DDL[DDL_SIZE];
} SQL_Map;
typedef struct {
  char *s;
  int quoted;
} Tok;
typedef struct {
  Tok t[TOKMAX];
  int n, p;
} Parser;
typedef struct {
  char name[64], type[16], format[256], match[512];
  char cap[CAPMAX][64], captype[CAPMAX][16];
  int nc, parent, record, min, max, notnull, hasdefault, defnull, strict;
  char def[1024];
  regex_t re;
  int compiled;
} Node;
typedef struct {
  Node node[NODES];
  int n, unmatched, links, virtualrel;
} Schema;
typedef struct {
  char *name, *value;
  int numeric;
} Capture;
typedef struct {
  int field, isnull;
  char *path;
  struct stat st;
  Capture cap[CAPMAX];
  int nc;
  struct Value *value;
} Member;
typedef struct {
  char *path;
  Capture cap[NODES];
  int nc;
  Member *m;
  int nm;
  struct Value *values;
} Record;
typedef struct {
  void *address;
  u32 *previous, *word;
  size_t size;
} SQL_TraceScope;
typedef struct {
  int fd;
  /* A staged relation retains its locked physical definition for live Trace.
   * Data/schema reads still use the private transaction snapshot. */
  int live_root, has_live_root;
  SQL_TraceScope trace;
  char path[PATH_MAX];
  SQL_Map map;
  Schema schema;
  Record *r;
  int nr;
} Table;
typedef struct SQL_Session SQL_Session;
typedef struct {
  SQL_Result *out;
  SQL_Status status;
  SQL_Options opt;
  int route_new; /* CREATE/DEFINE may stage a not-yet-defined directory */
  char cwd[PATH_MAX];
  FILE *stream;
  char *buf;
  size_t len;
  SQL_Session *session;
  const char *verb, *statement;
  Parser *parser;
  unsigned participant;
  int no_context, deferred, quiet_recovery, provisioning, missing_null;
  int pinned_view_fd; /* internal one-shot fd+1 for watcher reconciliation */
  int query_depth, view_depth;
  int returning_active;
  int raw_stream; /* projection of a one-value RAW SELECT may stream */
  /* Trigger WHERE scope: event_kind/event_field/event_path/event_record. */
  int event_scope;
  int coordinating; /* COMMIT holds participant locks: anchors read lock-free */
  const char *event_kind, *event_field, *event_path, *event_record;
  char view_stack[16][PATH_MAX];
} Env;
void *sql_mapping(Env *, int, size_t, int);
void sql_unmapping(void *);
int sql_trace_map(Env *, int, size_t, size_t, int, SQL_TraceScope *);
void sql_trace_unmap(SQL_TraceScope *);
int sql_trace_store(Env *, int, size_t, size_t, uint32_t);
int sql_trace_object_set(Env *, const char *, int, uint32_t);
int sql_context_trace_set(Env *, const char *, uint32_t);
SQL_Status sql_run(const char *, int (*)(Env *, Parser *), const char *,
                   const SQL_Options *, SQL_Result *);
int sql_autocontext(Env *, Parser *);
int sql_provisioned_metadata(Env *, int, const char *);
int SQLi_fail(Env *, SQL_Status, const char *, ...);
int SQLi_lex(Env *, Parser *, const char *);
void SQLi_parser_free(Parser *);
int SQLi_is(Parser *, const char *);
int SQLi_eat(Parser *, const char *);
int SQLi_need(Env *, Parser *, const char *);
char *take(Env *, Parser *);
int SQLi_end(Env *, Parser *);
int SQLi_schema_parse(Env *, Parser *, Schema *);
void SQLi_schema_free(Schema *);
int SQLi_schema_text(Env *, const char *, Schema *);
int sql_safe_relative(const char *);
int sql_parentfd(Env *, int, const char *, char *);
int SQLi_component(const char *);
int SQLi_joinpath(Env *, char *, const char *, const char *);
int SQLi_open_dir(Env *, const char *);
int SQLi_lockdir(Env *, int, int);
int SQLi_map_read(Env *, int, const char *, SQL_Map *);
int SQLi_map_write(Env *, int, const char *, SQL_Map *, int);
int SQLi_map_valid(Env *, SQL_Map *);
int SQLi_table_open(Env *, Table *, const char *, int);
void SQLi_table_close(Table *);
int SQLi_schema_record_path(Env *, Schema *, const char *);
int SQLi_field_name_unique(Env *, Schema *, int, const char *);
int SQLi_field_name_check(Env *, Node *, const char *);
int SQLi_field_filename(Env *, Node *, unsigned, char *, size_t);
int SQLi_field_filename_at(Env *, Schema *, Node *, const char *, unsigned, char *, size_t);
int SQLi_format_count(const char *);
int SQLi_format_name(Env *, const char *, const unsigned long long *, int, char *, size_t);
int SQLi_format_parse(const char *, const char *, unsigned long long *, int *);
int SQLi_node_matches(Node *, const char *);
int SQLi_path_values(Schema *, const char *, unsigned long long *, int *);
int SQLi_generate_record(Env *, Table *, const char *, const unsigned long long *, int, char *, size_t);
int sql_id_lookup(Env *, Table *, const char *, char *);
int sql_ids_adopt(Env *, Table *, int *, int *, int *);
int SQLi_scan_table(Env *, Table *, int);
int SQLi_value_check(Env *, Node *, const unsigned char *, size_t);
int SQLi_member_target(Env *, Table *, Member *, char *);
int SQLi_member_load(Env *, Table *, Member *, unsigned char **, size_t *);
int SQLi_load_bytes(Env *, int, const char *, unsigned char **, size_t *);
#define STREAMMAX (1ull << 40) /* streamed FILE import / RAW output bound */
int SQLi_open_payload(Env *, int, const char *, int *, size_t *, unsigned long long);
int SQLi_value_check_bytes(Env *, Node *, const unsigned char *, size_t);
int SQLi_media_check(Env *, Node *, const unsigned char *, size_t);
int SQLi_value_check_fd(Env *, Node *, int, size_t);
int SQLi_copy_fd(Env *, int, int, size_t, unsigned long long *);
int SQLi_stream_out(Env *, int, size_t, FILE *);
void SQLi_json(FILE *, const unsigned char *, size_t);
void SQLi_shellquote(FILE *, const char *);
int sql_schema_cmd(Env *, const char *, Parser *);
int sql_select_cmd(Env *, Parser *);
int sql_mutate_cmd(Env *, const char *, Parser *);
int sql_admin_cmd(Env *, const char *, Parser *);
int sql_trigger_cmd(Env *, const char *, Parser *);
int sql_view_watch(Env *, Parser *);
/* Expression trees are compiled completely before any row evaluation. */
typedef struct Expr Expr;
typedef struct Value {
  unsigned char *s;
  size_t n;
  int null, numeric, binary, boolean, collection;
  int stream_fd1; /* fd+1 of a streamed (>64 MiB) RAW payload, 0 if none */
  struct Value *items;
  size_t count;
} Value;
typedef struct {
  int np, nr;
  int linked_fd; /* 0 saved-only; -1 validate links; fd+1 publish while source
                    locked */
  char names[NODES][64];
  Value **rows;
  char source[PATH_MAX], query[DDL_SIZE];
  uint64_t device, inode;
} SQL_QueryResult;
typedef struct {
  uint32_t magic, version, bytes, endian, TraceLevel, reserved;
  uint64_t generation, Device, Inode;
  char Source[PATH_MAX], Query[DDL_SIZE];
} SQL_ViewMap;
#define SQL_VIEW_MAGIC 0x31565753u
/* RETURNING: projections compiled against the target schema before commit. */
typedef struct {
  Expr *proj[NODES];
  int np;
  int expand; /* field expanded by PATH()/CONTENT() (one row per member), or -1 */
} SQL_Returning;
int sql_expr_expand_field(Expr *, Schema *);
void sql_output_value(FILE *, Value *);
Expr *sql_expr_ident(Env *, const char *);
int sql_expr_is_star(Expr *);
int sql_returning_split(Env *, Parser *, Parser **);
int sql_returning_prepare(Env *, Parser *, Schema *, SQL_Returning *);
int sql_returning_emit(Env *, SQL_Returning *, Table *, char *const *, int,
                       FILE *);
void sql_returning_free(SQL_Returning *);
int sql_dep_open(Env *, int, int);
int sql_dep_register(Env *, const char *, const char *, int);
int sql_dep_unregister(Env *, const char *, const char *, int);
int sql_dep_scan(Env *, int, int, FILE *, const char *);
int sql_dep_restrict(Env *, int, const char *);
int sql_dep_show(Env *, Parser *);
int SQLi_schema_dir_path(Schema *, const char *);
int sql_purge_view(Env *, int);
int sql_purge_table(Env *, Table *);
int sql_schema_serialize(Env *, Schema *, char *, size_t);
int sql_alter_schema(Env *, Table *, Parser *);
int sql_xshare_split(const char *, char *, char *);
int sql_xshare_load(Env *, const char *, unsigned char **, size_t *);
int sql_xshare_stat(Env *, const char *, struct stat *);
int sql_xshare_validate(Env *, Table *, const char *, const struct stat *,
                        const unsigned char *, size_t);
int sql_xshare_write(Env *, const char *, const struct stat *,
                     const unsigned char *, size_t);
int sql_xshare_link_source(Env *, Table *, const char *, const char *, char *,
                           unsigned char **, size_t *, Table *);
int sql_xshare_registered(Env *, Table *, const char *);
int sql_xshare_show(Env *, Parser *);
int sql_dep_register_fd(Env *, int, const char *, int);
int sql_dep_paths(Env *, int, const char *, char ***, int *);
int sql_dep_paths_live(Env *, int, const char *, char ***, int *);
#define SQL_BRANCH_MAX 8
typedef struct {
  char Name[64];
  uint64_t Device, Inode;
  SQL_ViewMap View;
} SQL_ViewBranch;
typedef struct {
  uint32_t magic, version, bytes, endian, TraceLevel, flags;
  uint64_t generation, Device, Inode;
  uint32_t UID, Count;
  SQL_ViewBranch Branch[SQL_BRANCH_MAX];
} SQL_MultiView;
int sql_purge_multiview(Env *, int, SQL_MultiView *);
int sql_multiview_kind(Env *, int);
int sql_multiview_read(Env *, int, SQL_MultiView *);
int sql_multiview_sources(Env *, int, SQL_ViewMap *);
int sql_multiview_create(Env *, Parser *, const char *);
int sql_multiview_admin(Env *, int, const char *, Parser *);
int sql_multiview_select(Env *, Parser *);
int sql_multiview_mem(int, char **);
int sql_multiview_reconcile(Env *, int);
int sql_view_directory(Env *, const char *, int);

int sql_linked_prune(Env *, int, unsigned, unsigned, unsigned *, unsigned *);
int sql_linked_refresh(Env *, int, Table *, Record **, size_t, const int *, int,
                       char[NODES][64], const char *);
int sql_query(Env *, Parser *, SQL_QueryResult *);
void sql_query_free(SQL_QueryResult *);
int sql_relation_open(Env *, Table *, const char *);
int sql_view_read(Env *, int, SQL_ViewMap *);
int sql_view_write(Env *, int, SQL_ViewMap *, int);
int sql_view_cmd(Env *, const char *, Parser *, const char *);
int sql_viewmem_cli(int, char **);
int sql_object_generation(Env *, int, uint64_t *);
int sql_object_generation_or_none(Env *, int, uint64_t *);
int sql_session_staged_view(Env *, const char *);
int sql_view_validate(Env *, SQL_ViewMap *);
int sql_tokens_text(Env *, Parser *, int, int, char *, size_t);
Expr *SQLi_expr_parse(Env *, Parser *);
void SQLi_expr_free(Expr *);
int SQLi_expr_eval(Env *, Expr *, Table *, Record *, Member *, Value *);
int SQLi_expr_validate(Env *, Expr *, Schema *, int);
int sql_utf8(const unsigned char *, size_t);
int SQLi_predicate(Env *, Expr *, Table *, Record *, Member *);
void SQLi_value_free(Value *);
int SQLi_field_id(Schema *, const char *);
int SQLi_record_member(Record *, int, int);
/* Durable, per-table redo journal. Readers refuse outstanding decisions. */
typedef struct {
  int fd, root, count, schema_changed;
  char name[80];
} Batch;
int sql_fanout_plan(Env *, Batch *);
int sql_permission_preflight(Env *, Batch *);
int sql_fanout_drain_root(Env *, const char *);
void sql_fanout_drain(Env *);
int SQLi_batch_put_fd(Env *, Batch *, const char *, int, size_t);
int sql_tree_excluded(const char *, const char *);
int sql_preflight(Env *, Batch *);
int sql_batch_preview(Env *, Batch *, int);
int SQLi_batch_begin(Env *, int, Batch *);
int SQLi_batch_put(Env *, Batch *, const char *, const void *, size_t);
int SQLi_batch_op(Env *, Batch *, char, const char *, const char *);
int sql_command_data(Env *, Batch *, char, const char *, const char *);
int SQLi_batch_commit(Env *, Batch *);
void SQLi_batch_abort(Batch *);
int SQLi_recover(Env *, int, int);
int SQLi_pending(Env *, int);
#include "sql_session.h"
#endif
