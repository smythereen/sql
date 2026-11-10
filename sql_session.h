/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef SQL_SESSION_H
#define SQL_SESSION_H
#define SQL_CTX_MAGIC 0x32585443u
#define SQL_COORD_MAGIC 0x32445243u
#define SQL_TX_TABLES 16
#define SQL_CTX_IDLE 0
#define SQL_CTX_ACTIVE 1
#define SQL_CTX_COMMITTING 2
#define SQL_OUTCOME_NONE 0
#define SQL_OUTCOME_COMMITTED 1
#define SQL_OUTCOME_ROLLED_BACK 2
#define SQL_OUTCOME_CONFLICT 3
/* Native v2, bounded pointer-free context. Only configuration is mem-editable.
 */
typedef struct {
  char Path[PATH_MAX];
  uint64_t Generation, Device, Inode;
} SQL_ContextEntry;
#define SQL_COMMAND_TEXT 65536
#define SQL_COMMAND_VALUES 65536
#define SQL_LINEAGE_MAX 128
#define SQL_CMD_NONE 0
#define SQL_CMD_ACCEPTED 1
#define SQL_CMD_EXECUTING 2
#define SQL_CMD_DECIDED 3
#define SQL_CMD_APPLIED 4
#define SQL_CMD_FAILED 5
typedef struct {
  uint32_t PID, Parent, UID, reserved;
  uint64_t Birth;
} SQL_Ancestor;
typedef struct {
  char Name[64];
  uint32_t Type, Offset, Length, reserved;
} SQL_CommandBinding;
typedef struct {
  uint32_t Token, reserved;
  uint64_t Size, Hash, Device, Inode;
  char Name[64];
} SQL_CommandInput;
typedef struct {
  uint64_t Sequence;
  uint32_t Phase, Status, BindingCount, ValueLength, TextLength, InputCount,
      LocalTable, reserved;
  char Verb[16], Transaction[33], LocalTransaction[33], Cwd[PATH_MAX],
      LocalRoot[PATH_MAX];
  uint16_t Output;
  uint32_t LockTimeout;
  uint64_t LocalDevice, LocalInode;
  char Text[SQL_COMMAND_TEXT];
  SQL_CommandBinding Binding[64];
  unsigned char Values[SQL_COMMAND_VALUES];
  SQL_CommandInput Input[64];
} SQL_Command;
_Static_assert(offsetof(SQL_Command, LocalDevice) == 8320,
               "bounded command options occupy former alignment bytes");
typedef struct {
  uint32_t magic, version, bytes, endian, TraceLevel, LockTimeout, Output,
      State;
  uint32_t UID, PID, ReadOnly, Count, Outcome, LineageVersion;
  uint64_t LineageHash;
  uint64_t Birth;
  char Boot[40], Nonce[33], Txid[33], Root[PATH_MAX];
  SQL_ContextEntry Table[SQL_TX_TABLES];
  uint32_t LineageCount, PriorPID, PriorUID, reserved;
  uint64_t PriorBirth;
  char PriorBoot[40], PriorNonce[33];
  SQL_Ancestor Lineage[SQL_LINEAGE_MAX];
  SQL_Command Command;
} SQL_ContextMap;
_Static_assert(offsetof(SQL_ContextMap, LineageVersion) == 52 &&
                   offsetof(SQL_ContextMap, LineageHash) == 56 &&
                   offsetof(SQL_ContextMap, Birth) == 64,
               "ancestry must occupy the legacy reserved payload bytes");
/* Page-separated dual slots retain the previous valid context across a torn
 * update. Hash covers sequence + pointer-free payload; no live-slot mutation.
 */
#define SQL_CTX_FILE_MAGIC 0x33464353u
typedef struct {
  uint64_t Sequence, Hash;
  SQL_ContextMap Value;
} SQL_ContextRecord;
#define SQL_CTX_SLOT_BYTES (((sizeof(SQL_ContextRecord) + 4095) / 4096) * 4096)
typedef struct {
  SQL_ContextRecord Record;
  unsigned char Padding[SQL_CTX_SLOT_BYTES - sizeof(SQL_ContextRecord)];
} SQL_ContextSlot;
typedef struct {
  uint32_t magic, version, bytes, endian;
  uint32_t LiveTraceLevel, TraceVersion;
  unsigned char Padding[4096 - 24];
  SQL_ContextSlot Slot[2];
} SQL_ContextFile;
_Static_assert(sizeof(SQL_ContextSlot) % 4096 == 0,
               "context slots must not share pages");
struct SQL_Session {
  int fd, root, workspace, registry, reconciled, admin_identity, closed;
  int recording;
  SQL_TraceScope trace;
  char path[PATH_MAX], name[80];
  SQL_ContextMap map;
};
typedef struct {
  uint32_t magic, version, bytes, UID, Count, reserved[3];
  char Txid[33], Root[PATH_MAX];
  SQL_ContextEntry Table[SQL_TX_TABLES];
} SQL_CoordManifest;
typedef struct {
  uint32_t magic, bytes;
  char Root[PATH_MAX], Txid[33];
} SQL_CoordRef;
typedef struct {
  pid_t pid, parent;
  uid_t uid;
  uint64_t birth;
  char state, comm[256];
} SQL_Process;
int sql_process_info(pid_t, SQL_Process *);
int sql_boot(char *);
int sql_lineage_capture(Env *, SQL_ContextMap *);
int sql_lineage_state(SQL_ContextMap *);
int sql_registry(Env *, int, int);
int sql_workspace_open(Env *, const char *, SQL_Session *, int, int);
void sql_workspace_close(SQL_Session *);
int sql_workspace_remove(Env *, SQL_Session *);
int sql_workspace_resume(Env *, Parser *);
int sql_rebind_pending(Env *, SQL_Session *);
int sql_workspace_migrate(Env *, Parser *);
int sql_legacy_read(Env *, int, SQL_ContextMap *);
int sql_command_start(Env *);
int sql_command_finish(Env *);
int sql_command_local(Env *, const char *, int);
int sql_command_decided(Env *);
int sql_command_reconcile(Env *);
int sql_command_inputs_check(Env *, SQL_Session *);
int sql_command_proof_store(Env *, SQL_Session *);
int sql_command_proof_restore(Env *, SQL_Session *);
int sql_command_valid(Env *, SQL_Command *);
int sql_command_inspect(Env *, SQL_Session *);
int sql_transactions_list(Env *, Parser *);
int sql_process_lineage(pid_t, uint64_t *, int *);
int sql_lineage_guard(Env *, SQL_ContextMap *);
int sql_uuid(Env *, char *);
int sql_write_all(int, const void *, size_t);
int sql_read_all(int, void *, size_t);
int sql_regular_open(Env *, int, const char *, int, struct stat *);
int sql_ctx_read(Env *, int, SQL_ContextMap *, int);
int sql_ctx_save(Env *, SQL_Session *);
int sql_ctx_valid(Env *, SQL_ContextMap *, int);
int sql_root_check(Env *, int);
int sql_session_load(Env *, const char *, const char *, int);
void sql_session_close(Env *);
int sql_session_route(Env *, Table *, int);
int sql_session_cmd(Env *, const char *, Parser *);
int sql_context_list(Env *, Parser *);
int sql_context_create(Env *, Parser *);
int sql_ctxmem_cli(int, char **);
int sql_context_active(Env *);
int sql_context_output(Env *);
int sql_stage_root(Env *, SQL_Session *, int);
int sql_tree_copy(Env *, int, int, const char *);
int sql_tree_remove(Env *, int, const char *);
int sql_tree_diff(Env *, int, int, const char *, Batch *, uint64_t);
int sql_snapshot_validate(Env *, int, const char *);
int sql_coord_commit(Env *, SQL_Session *);
int sql_coord_recover(Env *, int, const char *, int, const char *, int *);
int sql_coord_pending(Env *, int);
int sql_coord_outcome(Env *, int, const char *);
int sql_coord_ref(Env *, int, SQL_CoordRef *);
int sql_coord_attach(Env *, Batch *, SQL_Session *);
int sql_batch_begin_id(Env *, int, Batch *, const char *);
int sql_batch_prepare(Env *, Batch *);
int sql_batch_decide(Env *, Batch *);
int sql_batch_apply(Env *, Batch *, int);
int sql_batch_existing(Env *, int, const char *, Batch *);
int sql_batch_cleanup(Env *, Batch *);
int sql_batch_reclaim(Env *, int, const char *);
int sql_batch_put_file(Env *, Batch *, const char *, int);
#endif
