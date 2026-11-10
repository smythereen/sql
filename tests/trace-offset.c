/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
#include "sql_local.h"
int main(){printf("ctx trace offset %zu size %zu view trace %zu\n",offsetof(SQL_ContextFile,LiveTraceLevel),sizeof(SQL_ContextFile),offsetof(SQL_ViewMap,TraceLevel));}
