# sql — SQL commands for filesystem data

**User manual: [MANUAL.md](MANUAL.md)** (full grammar, defaults, filesystem effects, errors, verified examples; summary man page `sql.1`). The [language reference](filesystem-sql-language-reference.md) is the original design target; where it differs, MANUAL.md describes actual behaviour.

It builds with the [base](https://github.com/smythereen/base) unit make system, which handles C, C++, and Rust, including large mixed-language projects.

## Build and tests

```sh
cd ~/sql
make -j1 all
make test
make sanitize       # ASan + UBSan, including the seeded fuzz cases
make examples       # persistent direct C and C++ clients
```

Uses the existing `../rules.mak` / `../targets.mak` unit conventions. Installs `~/bin/sql`, command-name symlinks, `~/cmn/sql.h`, and `~/lib/libsql.a`. No other unit's sources are changed. `sql.c` follows the command-table approach in the real `far.c`, but requires exact commands instead of accepting ambiguous prefixes. Both forms work:

```sh
sql select 'title FROM /tmp/my-assets'
sql_select 'title FROM /tmp/my-assets'
```

Public operations have separate `sql_select.c` / `sql_select.o`-style files, separate from main. These API objects call shared C engine objects, not subprocesses. Python is used only for tests.

## A working example

```sh
sql create 'TABLE /tmp/my-assets (asset DIRECTORY RECORD (
    title TEXT NOT NULL,
    age INT64,
    image JPG [0-4]
)) LINKS INTERNAL'
cd /tmp/my-assets
sql insert "RECORD example (title,age) VALUES ('Hello',23)"
sql select 'title,age WHERE age >= 21 OUTPUT JSON'
sql select 'PATH(image) WHERE ANY(image, fs.mode = 0o750) OUTPUT NUL'
sql update "SET title = 'Revised' WHERE record = 'example'"
sql check 'TABLE TYPES'
```

Quotes surrounding a complete statement are **shell quoting**; quotes around values *inside* it are SQL quoting. SQL strings double their delimiter (`'can''t'`). Backslashes are literal; no shell evaluation, implicit script execution, or printf `%n` is allowed.

Pass the SQL statement as **one quoted argument** (or omit it for an empty statement). Multiple SQL-text argv fragments are refused instead of being joined lossily. For dynamic values, do not concatenate SQL:

```sh
sql insert --bind title TEXT "a title with ' quotes" \
    --bind age INT64 23 'RECORD another (title,age) VALUES (:title,:age)'
```

Omitted table means the exact invocation CWD. There is no ancestor search or implicit table adoption. A record subdirectory is not its parent table. Reads can omit WHERE; mutation requires a filter or explicit ALL scope.

## Direct C / C++ API

```c
#include <sql.h>
SQL_Result result;
SQL_Options options = {0};
options.cwd = "/tmp/my-assets";
SQL_Status status = SQL_Select("title,age", &options, &result);
/* result.data/result.size are owned bytes, not necessarily NUL-terminated text.
   On failure result.diagnostic describes it. No API writes normal stdout. */
SQL_Free(&result);
```

Link in this order:

```sh
cc -I$HOME/cmn client.c -L$HOME/lib \
  -lsql -ltrigger -lmio -lmap -lfar -lnow -lsem -lsys -lpthread
```

Use `g++` for a C++ client; the header has `extern "C"`. Tests compile and run both. Typed `SQL_Binding` arrays and lock timeouts are available through `SQL_Options`. Calls serialize this unit's use of legacy map/mio/sys process globals; callers must also coordinate any independent concurrent use of those units. Do not call these APIs from signal handlers or fork a multithreaded process into an SQL call without exec.

## Metadata tools

```sh
sql_tblmem /tmp/my-assets                 # replayable shell script to stdout
sql_tblmem /tmp/my-assets C.TraceLevel 0x01000000
sql_tblmem /tmp/my-assets C.TraceLevel 0
```

The map is validated before access. Header identity/generation is read-only; schema changes must parse and validate all records under the table lock. `C.DDL` changes use private-copy mio byte descriptors to avoid mio's 512-byte input buffer limit, then one durable map replacement. Dump replay restores logical settings, not immutable headers or historical generations. `.context/<pid>/.state` has its own verified dual-slot map and `sql_ctxmem` (`sql_contextmem` alias). It dumps individually quoted configuration assignments; owner/identity/transaction fields are read-only. All three mapped formats (`.table`, `.view`, context `.state`) have actual mio descriptors and checked MS_SYNC/file fsync durability after UpdateMap. `sql_viewmem view-directory` dumps TraceLevel and a saved Query; changing Query validates it before replacing metadata. Query edits without FROM resolve exact tool-invocation CWD, not the previous source. See [VIEWS.md](VIEWS.md).

Trace uses the real sys `TracePointer`: retained mappings bind it directly to their aligned shared mapped TraceLevel word, saving/restoring caller pointers in LIFO order before unmapping. No OR-mask snapshots are used. Table/view Trace-only edits update the original inode without advancing logical generation and are visible to existing mappings. Transaction snapshots retain a locked original definition for this live configuration; data/schema still come from the stage. Context Trace binds the stable header word, not a copied payload or a switchable checksum slot. See the pointer-identity/live-update tests in `tests/trace_scope.c`.

## Context directories and transactions

Provisioned contexts now live at **`dbroot/.context/<pid>/`**, with private mapped `.state`, complete pending `tables/<slot>/<record>/<field>` trees and immutable owned `inputs/<command-sequence>/` bytes. Context-attached execution saves the full verb, exact SQL text, typed binding bytes/lengths, effective options and command phase before effects. RESUME resolves journals; it never executes the saved SQL. See TRANSACTIONS.md for limits and migration.

Provision deliberately; a zero-filled map is never a usable context:

Explicit `sql context "CREATE"` uses nonempty `DATABASE_DIR`; missing/empty values error without CWD fallback. `CREATE ON '/chosen-root'` overrides it, and `CREATE ON '.'` explicitly uses current CWD. Environment paths are literal (relative paths use invocation CWD). Table targeting and other workspace policies are unchanged.

```sh
# /tmp/my-db must already exist; table paths must be inside it.
SQL_CONTEXT=$(sql context "CREATE ON '/tmp/my-db' OWNER $$")
export SQL_CONTEXT
cd /tmp/my-db/assets
sql begin 'READ WRITE'
sql update "SET title = 'Staged' ALL RECORDS"
sql commit 'RETURNING TRANSACTION'
sql context 'CLOSE'
unset SQL_CONTEXT
```

Omitted FROM still means exact CWD, never a context-selected table. Both implicit and explicit normal handles validate the complete persisted owner ancestry (PID/parent/UID/start for up to 128 processes), plus boot/start/nonce identity. Reparenting stops normal reuse without deleting work; explicit same-UID `RESUME handle` adopts a validated new lineage. Saved ancestry is independently checked, never accepted merely because sys lineage() first returns 1. READ ONLY, rollback, deferred final constraints and generation conflicts are implemented. SQL_Options.context selects the same engine from C/C++; `make examples` builds direct select and transaction clients in both languages. See [TRANSACTIONS.md](TRANSACTIONS.md) for the current precise grammar and important limits.

```sh
sql_ctxmem /tmp/my-db/.context/12345
sql_ctxmem /tmp/my-db/.context/12345 C.TraceLevel 0x01000000
sql_ctxmem /tmp/my-db/.context/12345 C.Output 2  # NUL framing
```

Current contexts own durable full staged row/field files, not references to changing FILE input paths: a tested input can be overwritten/deleted before commit and staged bytes still win. A killed staged operation retains its redo in the workspace; explicit RESUME reconciles its journal before further execution. `sql show "CONTEXTS ON '/tmp/my-db'"` lists verified owner/boot/state and pending transaction metadata without exposing parameter contents. `sql show "TRANSACTIONS ON '/tmp/my-db'"` discovers staged and coordinator work. `sql context "INSPECT 'handle'"` deliberately exposes full saved command/binding bytes and should be treated as sensitive. `CLEAN STALE` preserves busy mappings and unresolved contexts; it does not discard recoverable staged data because a shell died.

## Safety and durability boundary

Per-table autocommits use a sync'd redo journal, a durable commit decision, pinned directory descriptors, cooperative shared/exclusive table locks, and idempotent recovery. SQL readers refuse pending committed work. Individual path operations become visible to raw filesystem observers during apply: this is **not an atomic multi-path filesystem snapshot**. Do not edit managed files concurrently outside SQL. Hostile same-UID writers or writable ancestors are outside the tested threat model. Explicit contexts now support up to 16 non-overlapping tables under one checked coordinator, with durable global redo and generation conflict checks. This is not NFS/distributed/cross-database support. See [TRANSACTIONS.md](TRANSACTIONS.md).

A recovery exercise must use scratch data only:

```sh
SQL_TEST_CRASH=after-decision sql update "SET title = 'committed' ALL RECORDS"
# Test injection exits 86 after the durable decision.
sql recover 'TABLE ALL REPORT ONLY'
sql recover 'TABLE ALL APPLY'
```

`SQL_TEST_CRASH` and `SQL_TEST_FAIL` are developer fault-injection hooks. Never set them for ordinary use. See MANUAL.md and the unit tests for exact tested boundaries. Reclamation atomically retires completed journals before deleting payloads; recovery validates ownership/root proofs and never recursively erases an unproven directory.

## Additional accepted view work (not yet implemented)

Current `.view` objects are typed saved queries, not physical linked directory views. John additionally requires table-shaped view directories with linked field data, coherent membership refresh/dependencies and multiple named source-query branches with collision errors. Those remain required work; general JOIN/UNION semantics have not been invented or claimed.
