/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Direct API parity helper: no CLI engine or subprocess SQL dispatch. */
#include "sql.h"
#include <stdio.h>
int main(int argc,char **argv){
 if(argc!=3)return 2;SQL_Options options={0};options.cwd=argv[1];SQL_Result result={0};
 SQL_Status status=SQL_Context(argv[2],&options,&result);
 if(status)fprintf(stderr,"%s\n",result.diagnostic);else if(result.size)fwrite(result.data,1,result.size,stdout);
 SQL_Free(&result);return status;
}
