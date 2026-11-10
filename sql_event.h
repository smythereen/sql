/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Pointer-free ordinary durable event files, not mmap formats. */
#ifndef SQL_EVENT_H
#define SQL_EVENT_H
#include "sql_local.h"
#define SQL_EVENT_MAGIC 0x31564553u
#define SQL_EVENT_INSERT 1u
#define SQL_EVENT_UPDATE 2u
#define SQL_EVENT_DELETE 4u
#define SQL_EVENT_LINK 8u
#define SQL_EVENT_UNLINK 16u
#define SQL_EVENT_RENAME 32u
#define SQL_EVENT_ALL 63u
typedef struct {
  uint32_t Magic, Version, Bytes, UID, Kind, FieldCount;
  uint64_t Generation, Device, Inode, Length, Hash, HeaderHash;
  char Transaction[33];
  char Fields[64][64];
} SQL_EventHeader;
int sql_event_prepare(Env *, Batch *);
int sql_event_publish(Env *, int, int, const char *);
int sql_event_read(Env *, int, SQL_EventHeader *);
#endif
