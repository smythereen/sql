/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
#ifndef SQL_TRIGGER_META_H
#define SQL_TRIGGER_META_H
#include "sql_event.h"
#include "sql_local.h"
#define SQL_TRG_MAX 16
#define SQL_TRG_MAGIC 0x31525453u
typedef struct {
  uint32_t Used, Enabled, Kind, ArgCount, FieldCount, Timeout, Retries,
      LastStatus;
  uint64_t ExecDevice, ExecInode, Checkpoint, Delivered, Failures;
  char Name[64], Nonce[33], LastTransaction[33], Exec[PATH_MAX], Args[8][512],
      Fields[16][64], Definition[8192];
} SQL_TriggerDef;
typedef struct {
  uint32_t Magic, Version, Bytes, UID, Count, reserved;
  uint64_t Device, Inode;
  SQL_TriggerDef Trigger[SQL_TRG_MAX];
} SQL_TriggerMap;
typedef struct {
  uint64_t Sequence, Hash;
  SQL_TriggerMap Value;
} SQL_TriggerRecord;
#define SQL_TRG_SLOT (((sizeof(SQL_TriggerRecord) + 4095) / 4096) * 4096)
/* Version-1 maps keep their layout; skipped-delivery accounting lives in the
 * slot slack after the record, with its own magic and hash. A zero or invalid
 * extension reads as all-zero counters. Counters are bound to the trigger
 * nonce so a reused slot starts at zero. */
#define SQL_TRG_EXT_MAGIC 0x31585453u
typedef struct {
  uint32_t Magic, Version;
  uint64_t Sequence, NonceHash[SQL_TRG_MAX], Skipped[SQL_TRG_MAX], Hash;
} SQL_TriggerExt;
#define SQL_TRG_EXT_OFFSET ((sizeof(SQL_TriggerRecord) + 63) & ~(size_t)63)
_Static_assert(SQL_TRG_EXT_OFFSET + sizeof(SQL_TriggerExt) <= SQL_TRG_SLOT,
               "trigger extension must fit in the slot slack");
int sql_trg_skipped(Env *, int, const SQL_TriggerMap *, uint64_t[SQL_TRG_MAX]);
int sql_trg_save_skipped(Env *, int, SQL_TriggerMap *, unsigned, uint64_t);
typedef struct {
  uint32_t Magic, Version, Bytes, UID, LiveTraceLevel, TraceVersion;
  unsigned char Padding[4096 - 24];
  unsigned char Slot[2][SQL_TRG_SLOT];
} SQL_TriggerFile;
int sql_trg_definition(Env *, SQL_TriggerDef *);
int sql_trg_open(Env *, int, int);
int sql_trg_read(Env *, int, SQL_TriggerMap *);
int sql_trg_save(Env *, int, SQL_TriggerMap *);
int sql_trg_parse(Env *, Parser *, SQL_TriggerDef *, char **);
int sql_trg_exec_pin(Env *, SQL_TriggerDef *, int);
int sql_trgmem_cli(int, char **);
int sql_watch_engine(Env *, Parser *);
#endif

int sql_trg_fields(Env *, int, const SQL_TriggerDef *);
const char *sql_trg_where(const SQL_TriggerDef *);
