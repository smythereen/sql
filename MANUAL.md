# sql — filesystem SQL user manual

Version: sql unit on guardian, manual written 2026-11-09 after the final implementation of backlog items 1–10.
Every `console` example in this manual is executed by `tests/verify_manual.py` (part of `make test`)
against a fresh scratch directory `/tmp/sql-demo`; the shown output is the verified output. Within an
expected output line `<...>` stands for a run-specific value (UUIDs, PIDs, inode numbers).

`sql` treats an ordinary directory tree as a typed table: a *table* is a directory with a `.table`
definition, a *record* is a directory below it at the schema's `RECORD` level, and *fields* are the files
(or symlinks) inside the record directory. There is no server and no separate database file: the payload
bytes are the files themselves, and they stay readable by every ordinary program.

## Contents

1. Invocation, options and exit statuses
2. Lexical rules, quoting and parameters
3. Paths, defaults and environment
4. Data model and on-disk layout
5. Schema grammar (CREATE/DEFINE TABLE body)
6. CREATE TABLE, DEFINE TABLE, DESCRIBE TABLE
7. SHOW
8. SELECT and expressions
9. INSERT
10. UPDATE
11. DELETE
12. LINK and UNLINK (shared fields)
13. RETURNING
14. ALTER TABLE
15. DROP TABLE
16. CHECK
17. Views: CREATE/DEFINE/DESCRIBE/CHECK/DROP/ALTER VIEW
18. Transactions: BEGIN, COMMIT, ROLLBACK
19. CONTEXT
20. RECOVER
21. TRIGGER
22. WATCH
23. Event records
24. Dependencies and references
25. Map editors: tblmem, viewmem, ctxmem, trgmem
26. Limits
27. Diagnostics and error conditions
28. Durability, concurrency and crash behaviour
29. Unsupported forms (status 7) and decisions

Notation: grammar uses EBNF. `[ x ]` optional, `{ x }` zero or more, `x | y` alternatives, `( … )` grouping,
`'KW'` keywords (case-insensitive, never quoted), *path*/*string* are quoted string tokens,
*name* is an unquoted identifier, *uint* an unsigned decimal.

---

## 1. Invocation, options and exit statuses

```ebnf
invocation  = "sql" command { option } [ statement ]
            | "sql_" command { option } [ statement ] ;
command     = "create" | "define" | "describe" | "show" | "select" | "insert" | "update"
            | "delete" | "link" | "unlink" | "alter" | "drop" | "begin" | "commit"
            | "rollback" | "context" | "trigger" | "watch" | "check" | "recover"
            | "tblmem" | "viewmem" | "ctxmem" | "contextmem" | "trgmem" | "triggermem" ;
option      = "--context" handle | "--cwd" directory | "--lock-timeout" milliseconds
            | "--bind" name ( "TEXT" | "INT64" | "UINT64" | "BOOL" | "NULL" ) value ;
```

* The first word selects the command (exact match, no prefixes). `make all` also installs one
  `sql_<command>` alias per command in `~/bin`; `sql_select '…'` is identical to `sql select '…'`.
* The statement is **one shell argument**. Passing more than one argument after the options is refused
  (`pass the SQL statement as one quoted argument`, status 2) because rejoining shell words is lossy.
  An empty statement is valid for `begin`, `commit`, `rollback` and `context SHOW`-style forms that take
  no clauses (e.g. `sql begin ""`).
* Options come after the command word and before the statement:
  * `--context handle` — use this context workspace (same as `SQL_CONTEXT`; if both are given and differ,
    status 4 `conflicting option and environment contexts`).
  * `--cwd dir` — the directory that relative paths and the omitted table operand resolve against
    (default: the process working directory).
  * `--lock-timeout ms` — 1..3600000, default 5000. How long to wait for a table lock before status 3.
  * `--bind name TYPE value` — up to 64 typed parameters, referenced as `:name` (section 2).
* `sql --help` / `sql` with no command prints the command list (status 0 / 2).
* Results go to stdout only after the whole result was computed and validated; diagnostics go to stderr
  as `command: message`.

| Status | Name | Meaning |
|---|---|---|
| 0 | OK | success (including a write whose WHERE matched nothing) |
| 2 | SYNTAX | grammar, unknown identifier/function/keyword, bad literal |
| 3 | IO | open/read/write/fsync/lock-timeout/permission failures; nothing committed |
| 4 | CONSTRAINT | schema, cardinality, type, NOT NULL, dependency (RESTRICT), conflicts, refused unsafe states |
| 5 | NO_MATCH | `REQUIRE MATCH` found no rows |
| 6 | COMMITTED_PENDING | a durable decision exists but applying it did not finish; run `recover`, never retry blindly |
| 7 | UNSUPPORTED | a deliberately unimplemented form; nothing changed |

```console
$ sql
sql command [SQL clauses]
Commands: create define describe show select insert update delete link unlink alter drop begin commit rollback context trigger watch check recover tblmem ctxmem viewmem trgmem triggermem
[exit 2]
$ sql select "1" "2"
pass the SQL statement as one quoted argument
[exit 2]
```

## 2. Lexical rules, quoting and parameters

```ebnf
token      = quoted | punct | word ;
quoted     = "'" { char | "''" } "'" | '"' { char | '""' } '"' ;
punct      = "(" | ")" | "," | "[" | "]" | "=" | "<" | ">" | "!" | ";"
           | "<=" | ">=" | "!=" | "<>" ;
word       = char-except-space-and-punct { char-except-space-and-punct } ;
parameter  = ":" name ;            (* a word beginning with ':' *)
```

* Whitespace separates tokens. Keywords are case-insensitive and are only recognised **unquoted**: a
  quoted `'WHERE'` is a string, never a keyword.
* Both `'…'` and `"…"` quote; a doubled delimiter inside is one literal delimiter (`'it''s'`). Because the
  statement is usually inside shell quotes, the common idiom is `sql select "name WHERE name = 'x'"`.
* Paths, record paths, member names, regular expressions, FORMAT strings and executables are quoted
  strings. Field, capture, alias, trigger and branch names are unquoted words.
* A single trailing `;` is accepted and ignored.
* Numbers are words beginning with a digit or `-`; `NULL`, `TRUE`, `FALSE` are literals.
* `:name` is replaced by a bound value before parsing continues: TEXT becomes a quoted string, INT64/
  UINT64/BOOL become checked literals, NULL becomes `NULL`. Values never become SQL source, so a bound
  value cannot inject keywords. Unbound or doubly bound parameters are status 2. Bound TEXT may not
  contain NUL and is limited to 64 MiB.
* At most 8192 tokens per statement; expressions nest at most 64 levels.

```console
$ mkdir -p /tmp/sql-demo/lex && cd /tmp/sql-demo/lex
$ sql create "TABLE (item DIRECTORY RECORD (label TEXT))"
$ sql insert "RECORD 'q' (label) VALUES ('it''s WHERE')"
$ sql select --bind want TEXT "it's WHERE" "record WHERE label = :want"
[["q"]]
```

## 3. Paths, defaults and environment

* **Omitted table operand = the working directory.** Every command that names a table or view
  (`select … FROM`, `insert INTO`, `update path SET`, `delete FROM`, `alter TABLE path`, …) uses the exact
  invocation directory (or `--cwd`) when the operand is omitted. There is no upward search for a parent
  table and no `DATABASE_DIR` lookup for tables.
* Relative paths resolve against the working directory. Absolute paths are used as given.
* Path safety: `..` components are refused (`parent path components are not accepted`, status 4); every
  directory component is opened with `O_NOFOLLOW`, so a symlinked table/view directory is refused
  (status 3); all subsequent access is descriptor-relative so a renamed parent cannot retarget an
  operation mid-way.
* Record paths (`RECORD 'a/b'`, `RENAME RECORD`) are relative to the table root and must match the
  schema's directory levels.
* `DATABASE_DIR` is consulted only by `CONTEXT CREATE` without `ON` (section 19). `SQL_CONTEXT` names the
  context handle for every command (same as `--context`). Test-only variables (`SQL_TEST_*`,
  `SQL_FANOUT_DEBUG`) are documented in section 28.
* Autocommit context: every writing command (`create define insert update delete link unlink alter drop
  trigger watch`) that runs without an explicit context provisions a private workspace
  `<cwd>/.context/<parent-pid>/` (plus a `<cwd>/.sql-root` marker) so that the exact command and its redo
  are retained until applied. Reads never provision. `VALIDATE ONLY` and `TRIGGER SHOW` do not provision.

## 4. Data model and on-disk layout

```text
table-root/                     the table (CREATE makes it 0700 if missing)
├── .table                      pointer-free native map: magic/version/generation/TraceLevel/DDL text
├── .sql/                       private engine metadata (created on first need)
│   ├── events/<txid>           one durable event file per committed write (section 23)
│   ├── shared/<anchor>         shared-field payload anchors (LINK, section 12)
│   ├── ids/id-<dev>-<ino>      stable record-ID registry for adopted records
│   ├── deps/<kind>-<dev>-<ino> dependency intentions (views, linked consumers; section 24)
│   ├── .triggers               trigger registration map (section 21)
│   ├── watch.<nonce>           watcher checkpoint lease
│   ├── fanout/<txid>           pending cross-table notice intention (section 12)
│   └── fanin/<dev>-<ino>-<txid> notice receipt markers
├── .sql-journal.<txid>/        only while a write is being applied (redo; removed after DONE)
├── .sql-clean.<txid>/          retired journal being reclaimed (never replayed)
├── <group>/…/<record>/         directories per schema level; RECORD level = one record
│   ├── .sql-id                 32-hex immutable record ID (inserted records)
│   ├── <field>                 scalar field file (exactly-one or optional)
│   ├── <field>.<n>             collection members (1-based ordinal, sparse)
│   ├── <field>.jpg|.mp4|.sh    implicit extension for JPG/MP4/SH fields without MATCH
│   ├── .sql-null.<member>      marker: this zero-length member is SQL NULL
│   └── <field> -> ../…/.sql/shared/<anchor>   shared (linked) field
└── .context/<pid>/             context workspaces when the table root is also the cwd
```

* Names beginning with `.` are never records or fields; they are invisible to `SELECT *`.
* Changed payload files are written as private `0600` replacements; directories are `0700`.
  Unchanged imported files keep their identity and mode.
* NULL is a zero-length member plus its `.sql-null.<member>` marker — distinct from an empty string
  (zero-length, no marker) and from an absent member.
* Records inserted by SQL get `.sql-id`; records adopted by `DEFINE` (or `ALTER TABLE ADOPT IDS`) are
  identified through `.sql/ids/` keyed by inode + birth time, so original files are never modified.
* `.table`, `.view`, context `.state` and `.triggers` are exact-size, versioned, native-endian checked
  maps; decode/edit them only with the mem tools (section 25).

```console
$ mkdir -p /tmp/sql-demo/layout && cd /tmp/sql-demo/layout
$ sql create "TABLE 'people' (person DIRECTORY RECORD (name TEXT, age INT64, nick TEXT [0-1], tags TEXT [0-]))"
$ cd people
$ sql insert "RECORD 'alice' (name, age, tags, tags) VALUES ('Alice', 31, 'admin', 'ops')"
$ sql insert "RECORD 'bob' (name, age, nick) VALUES ('Bob', 17, NULL)"
$ ls -A alice bob
alice:
.sql-id
age
name
tags.1
tags.2

bob:
.sql-id
.sql-null.nick
age
name
nick
$ cat alice/name; echo
Alice
$ ls -A
.context
.sql
.sql-root
.table
alice
bob
```

## 5. Schema grammar

```ebnf
schema       = "(" node { "," node } ")" [ trailer ] ;
node         = name type { attribute } [ children ] ;
type         = "DIRECTORY" | "TEXT" | "INT64" | "UINT64" | "BOOL" | "OCTETS" | "JPG" | "MP4" | "SH" ;
children     = "(" node { "," node } ")" ;                 (* only after DIRECTORY *)
attribute    = cardinality | "RECORD" | "FORMAT" string | "MATCH" string
             | "CAPTURE" "(" capture { "," capture } ")"
             | "STRICT" | "NOT" "NULL" | "DEFAULT" ( value | "NULL" ) ;
cardinality  = "[" uint "]" | "[" uint "-" "]" | "[" uint "-" uint "]" ;
capture      = name [ "UINT64" | "INT64" | "TEXT" ] ;     (* default TEXT *)
trailer      = { "UNMATCHED" ( "ERROR" | "IGNORE" ) | "LINKS" ( "REJECT" | "INTERNAL" ) } ;
```

**Structure rules**

* Exactly one `DIRECTORY … RECORD` node. Any number of grouping `DIRECTORY` levels may sit above it.
* Fields (non-DIRECTORY nodes) must be direct children of the RECORD directory; no directories below
  the RECORD level.
* At most 64 nodes; names are unique across the whole schema (fields, directories and capture names
  must not collide); the schema text is at most 16384 bytes.

**Types**

| Type | Stored as | Validation |
|---|---|---|
| DIRECTORY | directory | name matches MATCH (if any) |
| TEXT | file | strict UTF-8, no NUL |
| SH | file, implicit `.sh` | strict UTF-8, no NUL; **never executed** by sql |
| INT64 / UINT64 | file, decimal | range-checked; newly written numbers canonicalised |
| BOOL | file | `true` / `false` (`TRUE`/`FALSE` literals) |
| OCTETS | file | any bytes |
| JPG | file, implicit `.jpg` | starts with FF D8 and ends with FF D9 (shallow check) |
| MP4 | file, implicit `.mp4` | minimal `ftyp` header (shallow check) |

**Attributes**

* `[n]`, `[n-m]`, `[n-]` — member cardinality per record (max 1000000). Leaf fields default to `[1]`
  (exactly one); DIRECTORY (and RECORD) levels default to `[0-]`. `[0-1]` is optional scalar; `max > 1`
  makes a collection whose members are named `<field>.<n>`.
* `RECORD` — marks the record level.
* `FORMAT 'fmt'` — how generated names are built (directories for `RECORD GENERATED`, members for
  collection inserts). Only literal text, `%%` and up to 8 conversions `%[width][.precision]u`
  (width/precision ≤ 64) are allowed. FORMAT does not restrict names supplied explicitly; use MATCH.
* `MATCH 'regex'` — POSIX extended regex that must match the **whole** file/directory name. Without
  MATCH a field's file name is derived from its name (plus implicit extension).
* `CAPTURE (c [TYPE], …)` — exposes regex groups 1..k of MATCH as typed pseudo-fields (≤ 8, requires
  MATCH, must not exceed the group count). Directory captures are record-level values; member
  captures are evaluated in member scope.
* `STRICT` — opt-in: refuse values that are not already canonical for the type.
* `NOT NULL` — the member may not be the SQL NULL form.
* `DEFAULT v | DEFAULT NULL` — used when INSERT omits the field and when ALTER ADD FIELD backfills.
* Trailer `UNMATCHED ERROR` (default): unknown entries in the tree are errors; `UNMATCHED IGNORE`: they
  are skipped. `LINKS REJECT` (default): symlinked fields are errors; `LINKS INTERNAL`: shared fields
  (symlinks to this or another table's `.sql/shared/`) are allowed. The trailer may also be written after
  the closing parenthesis in CREATE/DEFINE (section 6). DESCRIBE always prints the canonical trailer.

```console
$ mkdir -p /tmp/sql-demo/cam/2026/day05 /tmp/sql-demo/cam/2026/day06 && cd /tmp/sql-demo
$ printf '\377\330a\377\331' > cam/2026/day05/10_30.jpg
$ printf '\377\330bb\377\331' > cam/2026/day05/11_00.jpg
$ printf '\377\330c\377\331' > cam/2026/day06/09_15.jpg
$ sql define "TABLE 'cam' (year DIRECTORY MATCH '([0-9]{4})' CAPTURE (y UINT64) (day DIRECTORY RECORD MATCH 'day([0-9]{2})' CAPTURE (d UINT64) (shot JPG [0-] MATCH '([0-9]{2})_([0-9]{2})\.jpg' CAPTURE (hour UINT64, minute UINT64))))"
$ sql select "record, y, d, COUNT(shot) FROM 'cam' ORDER BY record"
[["2026/day05",2026,5,2],["2026/day06",2026,6,1]]
$ sql select "record, PATH(shot), hour, minute FROM 'cam' WHERE d = 5 ORDER BY record"
[["2026/day05","/tmp/sql-demo/cam/2026/day05/10_30.jpg",10,30],["2026/day05","/tmp/sql-demo/cam/2026/day05/11_00.jpg",11,0]]
$ sql define "TABLE 'cam2' (year DIRECTORY MATCH '[0-9]{4}' CAPTURE (y UINT64) (day DIRECTORY RECORD (x TEXT)))"
define: CAPTURE exceeds regex groups
[exit 4]
```

## 6. CREATE TABLE, DEFINE TABLE, DESCRIBE TABLE

```ebnf
create-table   = "TABLE" [ path ] schema { table-option } ;
define-table   = "TABLE" [ path ] schema { table-option } ;
table-option   = "VALIDATE" "ONLY" | "UNMATCHED" ( "ERROR" | "IGNORE" ) | "LINKS" ( "REJECT" | "INTERNAL" ) ;
describe-table = "TABLE" [ path ] [ "AS" "DDL" ] ;
```

* **CREATE** makes a new, empty table. The directory (default: cwd) may be missing — only its final
  component is created, mode 0700 — or must exist and be empty apart from SQL-provisioned metadata
  (`.context`, `.sql-root`). Otherwise status 4 `CREATE requires an empty existing directory; use DEFINE to
  adopt`. If a `.table` or `.view` already exists: status 4 `definition already exists`. Prints the
  canonical table path on success.
* **DEFINE** adopts an existing tree without touching its payload: it deep-scans and validates every
  entry against the schema (types included), then installs `.table` and registers stable IDs for the
  existing records. Any violation → status 4 and nothing is written.
* An entry whose name matches a level but has the wrong kind (a file where the level is a DIRECTORY
  without MATCH) is always an error (`expected real directory …`); `UNMATCHED IGNORE` only skips names
  that match no level.
* `VALIDATE ONLY` performs every check and writes nothing (and does not provision a context).
* Inside an explicit transaction CREATE/DEFINE are staged and published by COMMIT (an empty new
  directory may remain after ROLLBACK).
* **DESCRIBE** prints the stored schema text: the tokens as written by CREATE/DEFINE (single-spaced),
  or the fully expanded canonical form (`[1-1]`, `[0-]` …) once an ALTER has re-serialised it, followed
  by the canonical trailer. `AS DDL` prefixes `TABLE ` so the text can be reused
  as a CREATE/DEFINE statement for another path.

Filesystem effects: CREATE: table directory (if missing), `.table`, `.sql/events/<txid>`, and in the cwd
the autocommit workspace. DEFINE: `.table`, `.sql/ids/*`, event. DESCRIBE: none.

```console
$ cd /tmp/sql-demo
$ sql create "TABLE 'docs' (doc DIRECTORY RECORD (title TEXT, body TEXT)) LINKS INTERNAL"
$ sql describe "TABLE 'docs'"
( doc DIRECTORY RECORD ( title TEXT , body TEXT ) ) UNMATCHED ERROR LINKS INTERNAL
$ sql describe "TABLE 'docs' AS DDL"
TABLE ( doc DIRECTORY RECORD ( title TEXT , body TEXT ) ) UNMATCHED ERROR LINKS INTERNAL
$ sql create "TABLE 'docs' (doc DIRECTORY RECORD (title TEXT))"
create: definition already exists
[exit 4]
$ mkdir notempty && touch notempty/file
$ sql create "TABLE 'notempty' (x DIRECTORY RECORD (v TEXT))"
create: CREATE requires an empty existing directory; use DEFINE to adopt
[exit 4]
$ sql define "TABLE 'notempty' (x DIRECTORY RECORD MATCH 'r[0-9]+' (v TEXT)) VALIDATE ONLY"
define: unmatched filesystem entry file
[exit 4]
$ sql define "TABLE 'notempty' (x DIRECTORY RECORD MATCH 'r[0-9]+' (v TEXT)) UNMATCHED IGNORE VALIDATE ONLY"
$ sql define "TABLE 'notempty' (x DIRECTORY RECORD (v TEXT)) UNMATCHED IGNORE VALIDATE ONLY"
define: expected real directory file
[exit 4]
$ ls -A notempty
file
```

## 7. SHOW

```ebnf
show = "TABLES" "IN" path
     | "VIEWS" "IN" path
     | "TRANSACTIONS" "ON" path
     | "CONTEXTS" "ON" path
     | "DEPENDENTS" "OF" path
     | "REFERENCES" "OF" path ;
```

* `TABLES IN dir` / `VIEWS IN dir` — immediate children of *dir* holding a valid `.table` / `.view`,
  one JSON string per line (no recursion).
* `TRANSACTIONS ON root` — coordinated transactions under the coordinator *root*: staged ones and
  durable outcomes (`{"context":…,"busy":…}` lines for live workspaces).
* `CONTEXTS ON root` — every context workspace under *root*/.context with owner, liveness, lineage,
  state and outcome (section 19).
* `DEPENDENTS OF table` — live dependency entries (`{"kind":"view"|"link",…,"path":…}`), the same set
  DROP/ALTER RESTRICT checks.
* `REFERENCES OF table` — the table's shared anchors and which record/field/member use them.

```console
$ cd /tmp/sql-demo
$ sql show "TABLES IN '/tmp/sql-demo/layout'"
"people"
$ sql show "DEPENDENTS OF 'docs'"
```

## 8. SELECT and expressions

```ebnf
select      = projection { "," projection } [ "FROM" path ] [ "WHERE" expr ]
              [ "ORDER" "BY" expr [ "ASC" | "DESC" ] ] [ "LIMIT" uint ] [ "OFFSET" uint ]
              [ "OUTPUT" ( "JSON" | "LINES" | "NUL" | "RAW" ) ] [ "REQUIRE" "MATCH" ]
            | "BRANCH" name projection { "," projection } [ "WHERE" expr ] … ;   (* multi-view root *)
projection  = "*" | expr [ "AS" alias ] ;
expr        = and-expr { "OR" and-expr } ;
and-expr    = not-expr { "AND" not-expr } ;
not-expr    = "NOT" not-expr | comparison ;
comparison  = primary [ compop primary | "IS" [ "NOT" ] primary | "HAS" primary ] ;
compop      = "=" | "!=" | "<>" | "<" | "<=" | ">" | ">=" ;
primary     = "(" expr ")" | literal | identifier | function
            | "TIMESTAMP" string ;
function    = ( "PATH" | "CONTENT" | "COUNT" ) "(" field ")"
            | ( "ANY" | "ALL" ) "(" field "," expr ")" ;
literal     = string | number | "NULL" | "TRUE" | "FALSE" | parameter ;
identifier  = field | capture | "record" | "fs." property | "fs.target." property ;
property    = "type" | "mode" | "permissions" | "uid" | "gid" | "owner" | "group"
            | "size_bytes" | "mtime" | "atime" | "ctime" ;
```

**Source.** `FROM path` names a table or view; omitted FROM means the working directory. A view is
read through its saved query (nesting ≤ 16; cycles are errors).

**Identifiers.**
* A scalar field yields its typed value; NULL marker → `null`; an absent optional field → `null`.
* A collection field yields a JSON array of its members in bytewise filename order.
* `record` — the record's path relative to the table root.
* Captures (section 5) yield typed values; directory captures belong to the record.
* `*` — every declared leaf field and directory capture, in schema order (no hidden metadata).
* `fs.<property>` — `lstat` metadata of the **member in scope**. A member scope exists only inside
  `ANY/ALL(field, …)` or when the projection list contains exactly one `PATH(f)`/`CONTENT(f)`
  expansion; otherwise status 2/4 (`fs.* needs explicit member scope`). `fs.type` is one character
  (`f` regular, `l` symlink, `d` directory, …); `fs.mode`/`fs.permissions` are the 12 permission bits;
  times are epoch seconds. `fs.target.*` describes the regular file behind a shared-field symlink and is
  NULL for non-links.

**Functions.**
* `PATH(f)` / `CONTENT(f)` — expand collection *f* into one output row per member, giving the member's
  absolute path / value. At most one expanded collection per query.
* `COUNT(f)` — number of members (NULL members count).
* `ANY(f, pred)` / `ALL(f, pred)` — evaluate *pred* per member (member scope); empty ANY is false, empty
  ALL is true.

**Operators.** Comparisons are typed (numbers numerically, text bytewise). Three-valued logic: any
comparison with NULL is unknown; `IS NULL` / `IS NOT NULL` test it. `NOT`, `AND`, `OR` follow SQL
precedence (NOT > AND > OR). Unknown at the top of WHERE is false.

**Permission masks.** `fs.mode IS 'o:rw-,g:---,w:---'` is an exact test: three comma-separated groups
`o:` (owner), `g:` (group), `w:` (world), each three symbols from `r w x`, `-` (must be clear) or `.`
(don't care). `fs.mode HAS 'o:rw'` requires the listed bits and ignores the rest; shorthand groups may
list 1–3 letters (`g:rx`).

**TIMESTAMP 'YYYY-MM-DDTHH:MM:SS(Z|±HH:MM)'** — a calendar-validated instant converted to epoch seconds;
an explicit zone is mandatory.

**Ordering and paging.** `ORDER BY expr [ASC|DESC]` sorts by one expression (aliases are not
resolved; repeat the expression). Without ORDER BY the order is directory order. `LIMIT`/`OFFSET` apply
after sorting. At most 65536 result rows.

**Output framing.**
* `JSON` (default) — one array of row arrays plus newline. Integers and booleans stay JSON numbers/
  booleans; NULL is `null`; binary values or invalid UTF-8 are `{"$hex":"…"}`.
* `LINES` — one value per line; refuses NUL bytes, newlines, NULL, collections and binary (status 4).
* `NUL` — one value followed by a NUL byte (for `xargs -0`); refuses embedded NUL/NULL/collections.
* `RAW` — exactly one non-NULL scalar or member, bytes written unchanged (values > 64 MiB stream).
* `REQUIRE MATCH` — status 5 if the result is empty (the empty result is not printed).

**BRANCH.** In the root of a `LINKED BRANCHES` view, `SELECT BRANCH name …` queries that branch; FROM
is not allowed (query the branch directory directly instead).

```console
$ cd /tmp/sql-demo/layout/people
$ sql select "record, name, age, nick, tags ORDER BY record"
[["alice","Alice",31,null,["admin","ops"]],["bob","Bob",17,null,[]]]
$ sql select "name WHERE age >= 18 OR nick IS NOT NULL ORDER BY name OUTPUT LINES"
Alice
$ sql select "record, COUNT(tags) AS n WHERE ANY(tags, CONTENT(tags) = 'ops')"
[["alice",2]]
$ sql select "CONTENT(tags), fs.size_bytes, fs.mode IS 'o:rw-,g:---,w:---' WHERE record = 'alice'"
[["admin",5,true],["ops",3,true]]
$ sql select "name WHERE name = 'nobody' REQUIRE MATCH"
select: no matching result
[exit 5]
$ sql select "name WHERE fs.size_bytes > 1"
select: fs.* needs explicit member scope
[exit 2]
$ sql select "age FROM '/tmp/sql-demo/layout/people' WHERE record = 'bob' OUTPUT RAW"; echo
17
$ sql select "record WHERE ALL(tags, fs.mtime > TIMESTAMP '2020-01-01T00:00:00Z') ORDER BY record DESC LIMIT 1"
[["bob"]]
$ sql select "* WHERE record = 'bob'"
[["Bob",17,null,[]]]
```

## 9. INSERT

```ebnf
insert      = [ "INTO" path ] ( new-record | add-members ) [ returning ] ;
new-record  = "RECORD" ( string | generated ) "(" [ field { "," field } ] ")"
              "VALUES" "(" [ value { "," value } ] ")" ;
generated   = "GENERATED" [ "UNDER" string ] [ "USING" "(" uint { "," uint } ")" ] ;
add-members = "ADD" "TO" field "VALUES" "(" value { "," value } ")" target ;
value       = [ "NAMED" string ] ( literal | "FILE" "(" string ")" ) ;
target      = [ "WHERE" expr ] [ "ALL" "RECORDS" ] ;        (* at least one *)
```

* `RECORD 'g/r'` creates the record directory (and missing group directories), which must match the
  schema levels and must not exist. Fields are listed once per value; repeating a collection field adds
  several members (`(tags, tags) VALUES ('a','b')`). Omitted fields get their DEFAULT, else must be
  optional. At most 64 values.
* `RECORD GENERATED` names the record from the levels' FORMAT strings. Starting at `UNDER 'groups'`
  (default: table root), each lower level must be unambiguous and have FORMAT; values come from
  `USING (…)` in order (≤ 32); a single-conversion level without a USING value gets *highest existing
  + 1* (first is 1). For group levels the newest group is reused unless its RECORD level is full.
* `ADD TO field VALUES (…)` appends members to every record selected by the target; each member gets
  the next free ordinal `<field>.<n>` (a vacant lower ordinal may be reused; existing members are never
  renamed). For optional scalars (`[0-1]`) ADD TO creates the missing member.
* `NAMED 'file'` gives a member an explicit file name (must satisfy MATCH; required when MATCH-only names
  cannot be generated). `FILE('path')` imports bytes from a file (relative to cwd); files > 64 MiB are
  streamed (up to 1 TiB) without loading into memory.
* Values are checked against the field type before anything is written.

Filesystem effects: new directories 0700, member files 0600, `.sql-id`, NULL markers, event file.

```console
$ mkdir -p /tmp/sql-demo/photos && cd /tmp/sql-demo/photos
$ printf '\377\330hello\377\331' > /tmp/sql-demo/pic.jpg
$ sql create "TABLE (album DIRECTORY FORMAT 'album%u' (shot DIRECTORY RECORD [0-2] FORMAT 'shot%03u' (title TEXT, image JPG, rating UINT64 DEFAULT 3, tags TEXT [0-])))"
$ sql insert "RECORD GENERATED (title, image) VALUES ('Beach', FILE('/tmp/sql-demo/pic.jpg'))"
$ sql insert "RECORD GENERATED (title, image) VALUES ('Hill', FILE('/tmp/sql-demo/pic.jpg'))"
$ sql insert "RECORD GENERATED (title, image) VALUES ('Lake', FILE('/tmp/sql-demo/pic.jpg'))"
$ sql insert "RECORD GENERATED USING (7, 9) (title, image) VALUES ('Fixed', FILE('/tmp/sql-demo/pic.jpg'))"
$ sql select "record, title, rating ORDER BY record"
[["album1/shot001","Beach",3],["album1/shot002","Hill",3],["album2/shot001","Lake",3],["album7/shot009","Fixed",3]]
$ sql insert "ADD TO tags VALUES ('sea', 'sun') WHERE title = 'Beach'"
$ ls album1/shot001
image.jpg
rating
tags.1
tags.2
title
$ sql insert "RECORD 'album1/shot003' (title, image) VALUES ('Over', FILE('/tmp/sql-demo/pic.jpg'))"
insert: album1: shot count 3 outside [0-2]
[exit 4]
$ sql insert "RECORD 'album3/x' (title, image) VALUES ('Bad', 'not a jpeg')"
insert: invalid JPG value for image
[exit 4]
```

## 10. UPDATE

```ebnf
update  = [ path ] "SET" assign { "," assign } [ "WHERE" expr ]
          [ "ALL" ( "RECORDS" | "MEMBERS" ) ] [ returning ] ;
assign  = field "=" value ;
```

* Record mode (default): WHERE selects records; every assigned field must be a scalar
  (`[1]`/`[0-1]`) that exists in the record. Updating an absent optional member is refused
  (`INSERT ADD TO is required`). `SET f = NULL` writes the NULL form (refused for NOT NULL).
* Member mode: `ALL MEMBERS` with exactly one collection field: WHERE is evaluated per member (member
  scope: `CONTENT(f)`, member captures, `fs.*`) and every matching member is rewritten. Records
  without members are skipped.
* WHERE or an explicit `ALL RECORDS`/`ALL MEMBERS` is mandatory (status 2 otherwise).
* A matching nothing is status 0 with no change and no event.
* Updating a shared (linked) member writes the shared anchor, so every consumer sees the new value;
  same-table consumers are validated first.

```console
$ cd /tmp/sql-demo/photos
$ sql update "SET rating = 5 WHERE title = 'Beach'"
$ sql update "SET tags = 'SUN' WHERE CONTENT(tags) = 'sun' ALL MEMBERS"
$ sql select "title, rating, tags WHERE title = 'Beach'"
[["Beach",5,["sea","SUN"]]]
$ sql update "SET tags = 'x' WHERE title = 'Beach'"
update: collection UPDATE requires explicit ALL MEMBERS
[exit 4]
$ sql update "SET rating = 1"
update: UPDATE requires WHERE or ALL scope
[exit 2]
$ sql update "SET rating = 'high' ALL RECORDS"
update: invalid UINT64 value for rating
[exit 4]
```

## 11. DELETE

```ebnf
delete = [ "FROM" path ] [ "MEMBERS" field ] target [ returning ] ;
```

* Without MEMBERS: deletes every selected record directory (its managed files, NULL markers and
  `.sql-id`). A record containing unmanaged entries is refused (status 4) instead of deleting foreign
  data. Empty group directories are kept.
* `MEMBERS field`: deletes selected members (member scope WHERE, or `ALL MEMBERS`), then re-checks the
  field's minimum cardinality.

```console
$ cd /tmp/sql-demo/photos
$ sql delete "MEMBERS tags WHERE CONTENT(tags) = 'sea'"
$ sql delete "WHERE title = 'Fixed'"
$ sql select "record, tags ORDER BY record"
[["album1/shot001",["SUN"]],["album1/shot002",[]],["album2/shot001",[]]]
$ sql delete "MEMBERS title ALL MEMBERS"
delete: deleting members violates minimum cardinality
[exit 4]
```

## 12. LINK and UNLINK (shared fields)

```ebnf
link   = [ "FROM" path ] "FIELD" field "TO" string "FROM" "SOURCE" path target ;
unlink = [ "FROM" path ] "FIELD" field target ;
```

* Requires `LINKS INTERNAL` on the destination table. `TO 'record/member'` names one source member in
  the `SOURCE` table. The first link promotes the source member into a private anchor
  `.sql/shared/<32hex>` and replaces the source member with a relative symlink; every selected
  destination record's *field* becomes a symlink to the same anchor. No payload is copied.
* Cross-table links use absolute anchors in the owner table and register a `link` dependency on the
  owner (DROP of the owner is then RESTRICTed).
* Updating the value through any consumer writes the anchor. Cross-table consumers get logical
  UPDATE notices delivered after the owner commit (eventual; section 23).
* `UNLINK` materialises a private copy for the selected records (it does not delete data); the anchor
  remains while any member still references it.

```console
$ cd /tmp/sql-demo/docs
$ sql insert "RECORD 'a' (title, body) VALUES ('A', 'shared text')"
$ sql insert "RECORD 'b' (title, body) VALUES ('B', 'own text')"
$ sql link "FIELD body TO 'a/body' FROM SOURCE '.' WHERE title = 'B'"
$ readlink b/body
../.sql/shared/<...>
$ sql update "SET body = 'changed' WHERE title = 'A'"
$ cat b/body; echo
changed
$ sql show "REFERENCES OF '.'" | sort
{"anchor":"<...>","table":"/tmp/sql-demo/docs","record":"a","field":"body","member":"a/body"}
{"anchor":"<...>","table":"/tmp/sql-demo/docs","record":"b","field":"body","member":"b/body"}
$ sql unlink "FIELD body WHERE title = 'B'"
$ ls -l b/body | cut -c1
-
```

## 13. RETURNING

```ebnf
returning = "RETURNING" projection { "," projection } ;
```

Allowed on INSERT, UPDATE, DELETE, LINK and UNLINK (and `COMMIT RETURNING TRANSACTION`, section 18).
The projections are evaluated like SELECT over the affected records — post-image for writes, pre-image
for DELETE — and printed as JSON only after the commit is durable. At most one expanded collection.
Combining RETURNING with a streamed (> 64 MiB) FILE value is status 7.

```console
$ cd /tmp/sql-demo/photos
$ sql update "SET rating = 4 WHERE title = 'Hill' RETURNING record, rating"
[["album1/shot002",4]]
$ sql delete "WHERE title = 'Lake' RETURNING title"
[["Lake"]]
```

## 14. ALTER TABLE

```ebnf
alter-table = "TABLE" [ path ] alteration [ "VALIDATE" "ONLY" ] ;
alteration  = "RENAME" "RECORD" string "TO" string
            | "ADD" "FIELD" node                                  (* one leaf declaration *)
            | "DROP" "FIELD" name [ "INCLUDING" "DATA" ]
            | "RENAME" "FIELD" name "TO" name
            | "RENAME" "CAPTURE" name "TO" name
            | "ALTER" "FIELD" name ( "SET" field-set | "DROP" ( "STRICT" | "NOT" "NULL" | "DEFAULT" ) )
            | "SET" ( "UNMATCHED" ( "ERROR" | "IGNORE" ) | "LINKS" ( "REJECT" | "INTERNAL" ) )
            | "ADOPT" "IDS" ;
field-set   = "STRICT" | "NOT" "NULL" | "DEFAULT" ( value | "NULL" )
            | "CARDINALITY" cardinality | "TYPE" type ;
```

* `RENAME RECORD 'old' TO 'new'` moves a record (same depth; new path must match the schema and not
  exist); record ID and relative shared anchors are preserved. Emits a RENAME event.
* `ADD FIELD decl` — parsed exactly like a schema field. A required field (`min > 0`) on a non-empty
  table needs a DEFAULT, which is backfilled into every record in the same commit.
* `DROP FIELD f` — refused while members exist unless `INCLUDING DATA`, which deletes exactly the
  field's managed members (and NULL markers).
* `RENAME FIELD` — for fields without MATCH the member files are renamed in the same commit;
  `RENAME CAPTURE` renames a capture.
* `ALTER FIELD … SET CARDINALITY [m-n]` re-validates existing counts; `SET TYPE t` re-validates every
  value (changing to/from JPG/MP4/SH without MATCH would rename files → status 7); `SET NOT NULL`,
  `SET DEFAULT`, `SET STRICT` and the DROP forms change constraints after validating existing data.
* `SET UNMATCHED …` / `SET LINKS …` change the trailer (validated against the current tree).
* `ADOPT IDS` registers stable IDs for records without `.sql-id` and prunes dead registry entries;
  prints `{"adopted":n,"existing":n,"pruned":n}`. Not allowed inside a transaction (status 7).
* Renames/drops of a field referenced by a dependent view or trigger are refused (RESTRICT, status 4).
* `VALIDATE ONLY` runs all checks and the commit preflight without writing.

```console
$ cd /tmp/sql-demo/docs
$ sql alter "TABLE ADD FIELD pages UINT64 DEFAULT 1"
$ cat a/pages; echo
1
$ sql alter "TABLE RENAME FIELD pages TO npages"
$ ls a
body
npages
title
$ sql alter "TABLE DROP FIELD npages"
alter: field npages still has 2 member(s); use DROP FIELD npages INCLUDING DATA
[exit 4]
$ sql alter "TABLE DROP FIELD npages INCLUDING DATA"
$ sql alter "TABLE ADD FIELD extra TEXT"
alter: ADD FIELD extra [1-...] on 2 existing record(s) requires DEFAULT or minimum 0
[exit 4]
$ sql alter "TABLE RENAME RECORD 'b' TO 'b2'"
$ sql select "record ORDER BY record"
[["a"],["b2"]]
$ sql alter "TABLE ADOPT IDS"
{"adopted":0,"existing":2,"pruned":0}
```

## 15. DROP TABLE

```ebnf
drop-table = "TABLE" [ path ] [ "INCLUDING" "DATA" ] [ "CASCADE" | "RESTRICT" ] [ "VALIDATE" "ONLY" ] ;
```

* RESTRICT is the only behaviour (and the default): if live dependents exist (views on the table,
  tables linking to its anchors) the drop is refused, status 4, naming the first dependent.
  `CASCADE` is status 7.
* Plain DROP removes only the definition (`.table`); all payload stays in place and can be re-adopted
  with DEFINE.
* `INCLUDING DATA` removes only managed entries — record directories, field members, NULL markers,
  `.sql-id`, `.sql/` metadata — and preserves any unmanaged file (and the directories containing it).
* Inside a transaction DROP is staged and published by COMMIT.

```console
$ cd /tmp/sql-demo
$ sql drop "TABLE 'lex' VALIDATE ONLY"
$ sql drop "TABLE 'lex'"
$ ls -A lex
.context
.sql
.sql-root
q
$ sql define "TABLE 'lex' (item DIRECTORY RECORD (label TEXT)) UNMATCHED IGNORE"
$ sql select "label FROM 'lex'"
[["it's WHERE"]]
```

## 16. CHECK

```ebnf
check = "TABLE" [ path ] [ "ALL" | "SCHEMA" | "NAMES" | "COUNTS" | "TYPES" | "LINKS" | "JOURNALS" ] [ "DEEP" ]
      | "VIEW" [ path ] ;
```

`CHECK TABLE` validates names, structure, cardinalities, shared anchors and pending journals;
`TYPES` or `DEEP` also validates every value's type. Prints `ok: N records, …` or fails with status 4
naming the first problem. `CHECK VIEW` validates the saved query (and refreshes a LINKED view).

```console
$ cd /tmp/sql-demo
$ sql check "TABLE 'docs' ALL DEEP"
ok: 2 records, schema/names/counts/types
$ echo junk > layout/people/README
$ sql check "TABLE 'layout/people'"
check: expected real directory README
[exit 4]
$ rm layout/people/README
```

## 17. Views

```ebnf
create-view   = "VIEW" [ path ] ( "AS" "SELECT" query
                                | "LINKED" "AS" "SELECT" query
                                | "LINKED" "BRANCHES" "(" branch { ";" branch } ")" ) ;
branch        = name "AS" "SELECT" query ;
describe-view = "VIEW" [ path ] [ "AS" "DDL" ] ;
check-view    = "VIEW" [ path ] ;
drop-view     = "VIEW" [ path ] [ "INCLUDING" "DATA" ] [ "CASCADE" | "RESTRICT" ] [ "VALIDATE" "ONLY" ] ;
alter-view    = "VIEW" [ path ] "PRUNE" "GENERATIONS" [ "KEEP" uint ] ;
```
(`query` is the SELECT grammar without OUTPUT/REQUIRE.) CREATE and DEFINE are synonyms for views.

* **Saved view** (`AS SELECT`): an otherwise empty directory holding `.view` (pinned source path and
  device/inode, saved query). Reads re-run the query; the result columns are the projection aliases
  (default: field name, or `column_N` for computed expressions). Views are read-only (writes → 4).
  Omitted FROM in the definition means the cwd at definition time, saved canonically.
* **LINKED view**: additionally publishes a physical table-shaped tree
  `records -> .linked/<generation>/<record>/<alias>` whose entries are symlinks to the source fields
  (no copies). Only plain scalar projections are allowed (computed/collection/capture → 7). The tree is
  refreshed lazily by SELECT/CHECK VIEW, or continuously by `WATCH VIEW` (section 22). Old generations are
  pruned automatically (newest 8 kept, nothing younger than 60 s removed, any generation containing
  unmanaged content kept). `ALTER VIEW … PRUNE GENERATIONS [KEEP n]` (default KEEP 0) prunes explicitly —
  never the current generation; prints `{"views":n,"removed":n,"kept":n}`.
* **LINKED BRANCHES**: 1–8 named branches (letter, then letters/digits/`_`/`-`, ≤ 63 bytes), each its own
  LINKED view subdirectory; `SELECT BRANCH name …` from the root. Branches refresh independently (not
  one atomic snapshot).
* Creating a view registers a dependency in the source table (`.sql/deps`), so DROP TABLE / DROP or
  RENAME of a projected field is RESTRICTed while the view exists. Dropping the view removes the
  intention. DROP VIEW is definition-only unless `INCLUDING DATA` (removes the managed `records` link and
  `.linked` generations only).
* View DDL inside an explicit transaction is staged for saved views; LINKED/BRANCHES DDL in a
  transaction is status 7.

```console
$ cd /tmp/sql-demo
$ sql create "VIEW 'adults' AS SELECT name AS who, age FROM 'layout/people' WHERE age >= 18"
$ sql select "who FROM 'adults'"
[["Alice"]]
$ sql describe "VIEW 'adults' AS DDL"
VIEW AS SELECT name AS who , age FROM '/tmp/sql-demo/layout/people' WHERE age >= 18
$ sql update "'adults' SET age = 1 ALL RECORDS"
update: a VIEW or ambiguous definition is not a writable TABLE
[exit 4]
$ sql create "VIEW 'linked' LINKED AS SELECT name FROM 'layout/people' WHERE age >= 18"
$ readlink linked/records/alice/name
/tmp/sql-demo/layout/people/alice/name
$ sql show "DEPENDENTS OF 'layout/people'" | sort
{"kind":"view","path":"/tmp/sql-demo/adults"}
{"kind":"view","path":"/tmp/sql-demo/linked"}
$ sql drop "TABLE 'layout/people'"
drop: DROP TABLE refused (RESTRICT): 2 live dependent(s), first {"kind":"view","path":"<...>"}
[exit 4]
$ sql create "VIEW 'split' LINKED BRANCHES (grown AS SELECT name FROM 'layout/people' WHERE age >= 18 ; kids AS SELECT name FROM 'layout/people' WHERE age < 18)"
$ ls split
grown
kids
$ cd split && sql select "BRANCH kids name"
[["Bob"]]
$ cd /tmp/sql-demo && sql alter "VIEW 'linked' PRUNE GENERATIONS KEEP 0"
{"views":1,"removed":0,"kept":0}
$ sql show "VIEWS IN '.'" | sort
"adults"
"linked"
"split"
```

## 18. Transactions: BEGIN, COMMIT, ROLLBACK

```ebnf
begin    = { "READ" ( "ONLY" | "WRITE" ) | "ON" path | "CONTEXT" handle } ;
commit   = { "CONTEXT" handle | "RETURNING" "TRANSACTION" } ;
rollback = { "CONTEXT" handle } ;
```

* A transaction lives in an explicitly provisioned **context** (section 19). BEGIN never provisions one;
  without a context it fails with status 4 `context is not explicitly provisioned`. The context is found
  from `CONTEXT handle`, `--context`, `SQL_CONTEXT`, or else `<cwd>/.context/<parent-pid>` — i.e. the
  same shell that ran `context CREATE` in that directory.
* `ON root` must name the context's coordinator root (status 4 if it differs). `READ ONLY` refuses
  writes (status 4); default READ WRITE. Nested BEGIN is status 4.
* After BEGIN every SQL command from that shell (same parent pid) runs in the transaction: the first
  access to a table takes a durable private snapshot (≤ 16 tables); writes are staged; reads see the
  transaction's own staged state (repeatable reads); other processes keep seeing committed state.
* COMMIT locks the coordinator and the sorted participant tables, verifies that no participant changed
  since its snapshot (table-granular generation check), validates final constraints (cardinalities and
  NOT NULL may be violated temporarily inside the transaction, not at commit), writes one durable
  decision, applies every participant, then records DONE. A conflict is status 4 `transaction conflict
  … rollback and retry`. `RETURNING TRANSACTION` prints `{"transaction":"<32hex>","outcome":"committed"}`.
* ROLLBACK discards staged work. It cannot undo a durable commit.
* Readers that meet a decided-but-unapplied participant get status 6 rather than a partial view.
* Not transactional (status 7 inside a transaction): TRIGGER DDL, ADOPT IDS, LINKED view DDL,
  `RECOVER TABLE … TRANSACTION`. WATCH refuses to run inside a transaction (status 4).

```console
$ cd /tmp/sql-demo
$ sql context "CREATE ON '/tmp/sql-demo'"
context: PID workspace collision; preserve and explicitly RESUME/MIGRATE/archive prior work
[exit 4]
$ sql begin ""
$ sql update "'layout/people' SET age = 18 WHERE name = 'Bob'"
$ sql insert "INTO 'docs' RECORD 'c' (title, body) VALUES ('C', 'new')"
$ sql select "name, age FROM 'layout/people' ORDER BY name"
[["Alice",31],["Bob",18]]
$ sql commit "RETURNING TRANSACTION"
{"transaction":"<...>","outcome":"committed"}
$ sql begin "READ ONLY"
$ sql insert "INTO 'docs' RECORD 'd' (title, body) VALUES ('D', 'x')"
insert: read-only transaction cannot write
[exit 4]
$ sql rollback ""
$ sql begin ""
$ sql delete "FROM 'docs' WHERE title = 'C'"
$ sql rollback ""
$ sql select "title FROM 'docs' ORDER BY title"
[["A"],["B"],["C"]]
```

## 19. CONTEXT

```ebnf
context = "CREATE" [ "ON" path ] [ "OWNER" pid ]
        | "SHOW" [ handle ]
        | "SET" [ handle ] variable "=" value
        | "CLOSE" [ handle ]
        | "CLEAN" "STALE" "ON" path
        | "INSPECT" handle
        | "RESUME" handle [ "OWNER" pid ]
        | "MIGRATE" handle ;
variable = "Output" | "OUTPUT" | "LockTimeout" | "LOCK_TIMEOUT" | "TraceLevel" | "TRACE" ;
```

A context is a private workspace directory `<root>/.context/<owner-pid>/` (0700) containing a mapped
`.state` (dual checksummed slots), `tables/` snapshots, `commands/<n>/` retained command records, and a
root marker `<root>/.sql-root`. It is bound to its owner process (default: the parent of `sql`, i.e. your
shell), including the owner's birth time, boot ID and ancestry, so a recycled PID cannot hijack it.

* `CREATE [ON root] [OWNER pid]` — root is `ON` if given (an explicit `'.'` means cwd); otherwise the
  `DATABASE_DIR` environment variable; otherwise status 4 (no implicit cwd fallback). The root must
  exist. Prints the handle. CREATE never overwrites: if a workspace for that owner PID already exists
  under the root it fails with status 4 `PID workspace collision` and leaves it untouched. Note that the
  autocommit workspace created by your earlier writes in that directory (section 3) *is* such a
  workspace and is a complete context: BEGIN/COMMIT use it directly, so CREATE is only needed before the
  first write (or for another root/owner).
* `SHOW` — state (0 idle, 1 active, …), read-only flag, last outcome (1 committed, 2 rolled back),
  transaction ID and participating tables.
* `SET` — `LockTimeout` (1..3600000 ms), `Output` (JSON|LINES|NUL|RAW default framing), `TraceLevel`
  (uint32, stored in the live mapped trace word).
* `CLOSE` — removes an idle context (status 4 with unresolved work).
* `CLEAN STALE ON root` — removes idle workspaces of dead owners; **preserves** a dead owner's active or
  committed-pending work (reported as preserved recoverable context).
* `INSPECT handle` — read-only dump of the retained command, phase and inputs.
* `RESUME handle [OWNER pid]` — transfers an interrupted context (dead owner, or interrupted autocommit
  command) to a live same-UID process (default: your shell), then `recover` completes it.
* `MIGRATE handle` — converts a legacy single-file context into a workspace directory.

```console
$ cd /tmp/sql-demo
$ sql context "SET LockTimeout = 2000"
$ sql context "SHOW"
{"context":"/tmp/sql-demo/.context/<...>","state":0,"read_only":false,"outcome":2,"transaction":"<...>","tables":[<...>]}
$ sql context "SET Output = XML"
context: configuration requires a checked uint32
[exit 2]
$ env -u DATABASE_DIR sql context "CREATE"
context: CONTEXT CREATE requires ON root or nonempty DATABASE_DIR; no current-directory fallback
[exit 4]
$ sql context "CLOSE"
$ sql begin ""
begin: context is not explicitly provisioned
[exit 4]
```

## 20. RECOVER

```ebnf
recover = "TABLE" [ path ] ( "ALL" | "TRANSACTION" txid ) [ "APPLY" | "REPORT" "ONLY" ]
        | "DATABASE" [ path ] ( "ALL" | "TRANSACTION" txid ) [ "APPLY" | "REPORT" "ONLY" ] ;
```

* REPORT ONLY is the default: lists pending journals/transactions and their proven outcome.
* `APPLY` completes every durable decision (idempotent redo), discards undecided preparations (they
  carry an ABORT proof) and reclaims retired `.sql-clean.*` journals. Committed work is never rolled back.
* `DATABASE [root]` (default: the context root, else cwd) resolves coordinated multi-table transactions;
  participant tables of a coordinated transaction must be recovered with DATABASE.
* `TABLE … TRANSACTION id` is status 7 (use `DATABASE … TRANSACTION id`).
* After a crashed autocommit command, the owner runs `context RESUME <ctx>` and then
  `recover TABLE <t> ALL APPLY` (see section 28).

```console
$ cd /tmp/sql-demo
$ sql recover "TABLE 'docs' ALL"
$ sql recover "DATABASE '/tmp/sql-demo' ALL REPORT ONLY"
<...> committed/done
$ sql recover "TABLE 'docs' TRANSACTION 0123456789abcdef0123456789abcdef"
recover: TABLE transaction selection is not yet supported; use ALL or DATABASE TRANSACTION
[exit 7]
```

## 21. TRIGGER

```ebnf
trigger    = "INIT" [ "ON" path ]
           | "CREATE" name [ "ON" path ] "AFTER" event { "," event }
             [ "OF" ( field-list | "(" field-list ")" ) ] [ "WHERE" expr ]
             "EXECUTE" string "ARGUMENTS" "(" [ string { "," string } ] ")"
             { "TIMEOUT" uint | "RETRIES" uint | "ENABLE" | "ENABLED" | "DISABLE" | "DISABLED" }
           | "SHOW" [ "ON" path ]
           | ( "ENABLE" | "DISABLE" | "DROP" ) name [ "ON" path ] ;
event      = "INSERT" | "UPDATE" | "DELETE" | "LINK" | "UNLINK" | "RENAME" | "COMMIT" ;
field-list = field { "," field } ;
```

* `INIT` creates the registration map `.sql/.triggers` (16 slots). CREATE also initialises it.
* Triggers fire **after commit**, asynchronously, from a `WATCH` process (section 22) — never inside
  the writing command. `COMMIT` means all six kinds. New triggers start at the table's current
  generation (earlier events are not delivered).
* `OF fields` (≤ 16) matches only logical entries for those fields (record-level entries, field `""`,
  never match OF). `WHERE expr` is a record predicate evaluated against the record's **committed state
  at delivery time** plus pseudo-fields `event_kind` (`'INSERT'`…), `event_field`, `event_path`,
  `event_record`; for a deleted record all fields are NULL. WHERE ≤ 4096 bytes, validated at CREATE.
* `EXECUTE '/abs/path'` — absolute executable, pinned by identity at CREATE (replacing it later makes
  delivery fail rather than run something else). It runs with `ARGUMENTS` (≤ 8, ≤ 511 bytes each) as argv
  — no shell, no evaluation — stdin = the event JSON, stdout/stderr = /dev/null, environment
  `PATH=/usr/bin:/bin LANG=C.UTF-8`, its own process group.
* Exit 0 acknowledges the event. Non-zero, a signal (128+n) or `TIMEOUT` (1..60000 ms, default 5000;
  status 124) is a failure: the handler is retried up to `RETRIES` (0..8) times, then the checkpoint stays
  put and the same event is retried by the next WATCH run. Delivery is **at least once**.
* Default state is DISABLED unless ENABLE is given. `SHOW` prints name, enabled, checkpoint,
  delivered, skipped (events filtered out by kind/OF/WHERE), failures, last status and the WHERE text.
* Trigger DDL inside a transaction is status 7.

```console
$ cd /tmp/sql-demo
$ printf '#!/bin/sh\ncat >> /tmp/sql-demo/hook.log\necho >> /tmp/sql-demo/hook.log\n' > /tmp/sql-demo/hook.sh && chmod +x /tmp/sql-demo/hook.sh
$ sql trigger "CREATE adult ON 'layout/people' AFTER INSERT, UPDATE OF (age) WHERE age >= 18 EXECUTE '/tmp/sql-demo/hook.sh' ARGUMENTS ('people') TIMEOUT 2000 RETRIES 1 ENABLE"
$ sql insert "INTO 'layout/people' RECORD 'carol' (name, age) VALUES ('Carol', 40)"
$ sql insert "INTO 'layout/people' RECORD 'dan' (name, age) VALUES ('Dan', 5)"
$ sql watch "ON 'layout/people' FOR ALL ONCE"
{"delivered":1,"skipped":1,"wakeups":0,"overflows":0}
$ cat /tmp/sql-demo/hook.log
{"transaction":"<...>","generation":<...>,"table":"/tmp/sql-demo/layout/people","physical":[{"operation":"M","path":"carol"},{"operation":"P","path":"carol/name"},{"operation":"P","path":"carol/age"}],"logical":[{"event":0,"kind":1,"record":"carol","field":"age","path":"carol/age"},{"event":1,"kind":1,"record":"carol","field":"name","path":"carol/name"},{"event":2,"kind":1,"record":"carol","field":"","path":"carol"}]}

$ sql trigger "SHOW ON 'layout/people'"
[{"name":"adult","enabled":true,"checkpoint":<...>,"delivered":1,"skipped":1,"failures":0,"status":0,"where":"age >= 18"}]
$ sql trigger "DISABLE adult ON 'layout/people'"
$ sql trigger "DROP adult ON 'layout/people'"
$ sql trigger "CREATE bad ON 'layout/people' AFTER INSERT EXECUTE 'hook.sh' ARGUMENTS ()"
trigger: EXECUTE requires an absolute executable path
[exit 2]
```

## 22. WATCH

```ebnf
watch = [ "ON" path ] "FOR" ( "ALL" | name ) [ "ONCE" | "CONTINUOUS" ] [ "RESUME" ] [ "DURATION" uint ]
      | "VIEW" path { "DURATION" uint | "DEBOUNCE" uint } ;
```

* **Trigger watch** (`FOR ALL` or one trigger name): delivers every committed event after each
  trigger's checkpoint, in generation order, then (CONTINUOUS, the default) waits for new events using
  the trigger unit's inotify API, until `DURATION` ms (1..3600000) or SIGINT/SIGTERM. `ONCE` drains and
  exits. `RESUME` is accepted for clarity (checkpoints always resume). Prints a JSON summary
  `{"delivered","skipped","wakeups","overflows"}`. A watch also re-drives pending cross-table
  notices of the watched table (section 23). WATCH runs in its own process workspace
  (`.context/<watch-pid>`) and refuses explicit transactions.
* **View watch** (`VIEW path`): keeps a LINKED (or BRANCHES) view's `records` tree fresh while ordinary
  programs write the source files: startup rescan, close-write/rename/delete hints coalesced by
  `DEBOUNCE` ms (1..5000, default 100), plus a full reconciliation about every second. One watcher per
  view (`.sql-view-watch` lease). Prints refresh/failure counters at exit.
* No daemon is installed; run WATCH in the foreground or under your own supervisor.

```console
$ cd /tmp/sql-demo
$ sql watch "VIEW 'linked' DURATION 300 DEBOUNCE 50"
sql watch VIEW ready (filesystem refresh active)
{"refreshes":1,"failures":0,"last_status":0,"wakeups":0,"overflows":0}
$ ls linked/records
alice
bob
carol
```

## 23. Event records

Every committed write that changes something creates `.sql/events/<txid>` (JSON, fsynced, checksummed
header) — no-match writes create none. Format:

```text
{"transaction":"<32hex>","generation":N,"table":"/abs/table",
 "physical":[{"operation":"M|P|D|R|T|H|L|N","path":"…"}…],
 "logical":[{"event":i,"kind":K,"record":"r","field":"f","path":"r/f"}…]}
```

* Kinds: INSERT 1, UPDATE 2, DELETE 4, LINK 8, UNLINK 16, RENAME 32 (bit mask; COMMIT = 63).
* Logical entries are per member (field set) plus one record-level entry (field `""`) for record
  INSERT/DELETE/RENAME. RENAME entries carry the new path.
* Physical operations are the journal's: M mkdir, P put, D delete, R rmdir, T rename, H hardlink,
  L symlink, N notice (no filesystem change).
* **Cross-table notices.** When a table updates a shared anchor that other tables link to, the owner
  commit records a fan-out intention `.sql/fanout/<txid>`; after the owner command finishes, each
  consumer table receives one commit with `N` operations, i.e. logical UPDATE events for its linked
  members, de-duplicated by `.sql/fanin/` markers. If delivery is interrupted (crash, lock busy) it is
  re-driven by the next write of that anchor or by any WATCH on the owner — eventual, at least once.

## 24. Dependencies and references

* `.sql/deps/<kind>-<dev>-<ino>` in a source table records a dependent (a view or a linking table). The
  entries are intentions: checked for liveness when used (dead ones are pruned lazily) — `SHOW
  DEPENDENTS OF` lists only live ones.
* RESTRICT checks: DROP TABLE, DROP FIELD / RENAME FIELD / RENAME CAPTURE / SET TYPE of a projected
  field (lexical reference check), DROP VIEW of a view used by another view.
* `SHOW REFERENCES OF table` lists shared anchors and their members.

## 25. Map editors

```text
sql tblmem  table   [ C.TraceLevel uint32 | C.DDL 'schema' ]
sql viewmem view    [ C.TraceLevel uint32 | C.Query 'SELECT clauses' ]
sql ctxmem  context [ C.TraceLevel | C.LockTimeout | C.Output value ]
sql trgmem  table   [ C.TraceLevel uint32 | C.Trigger[index].Definition 'SQL' ]
```

Without an assignment the tool prints a replayable shell script (decoded fields as comments,
editable fields as assignments). Assignments go through the real mio descriptors, are validated (DDL
re-parsed and checked against the tree, queries re-pinned) and written with checked `MS_SYNC`/fsync.
Identities, checkpoints and lineage are read-only.

```console
$ sql tblmem /tmp/sql-demo/docs C.TraceLevel 2
$ sql tblmem /tmp/sql-demo/docs | grep TraceLevel
sql_tblmem '/tmp/sql-demo/docs' C.TraceLevel '2'
```

## 26. Limits

| Item | Limit |
|---|---|
| Statement tokens | 8192 |
| Expression nesting / view nesting | 64 / 16 |
| Schema nodes / schema text | 64 / 16384 bytes |
| Captures per node / FORMAT conversions | 8 / 8 (width, precision ≤ 64) |
| Cardinality maximum | 1000000 |
| Projections / values per INSERT / ADD TO values | 64 / 64 / 64 |
| Result rows | 65536 |
| In-memory value; streamed FILE / RAW value | 64 MiB; 1 TiB |
| Tables per transaction | 16 |
| Triggers per table / OF fields / arguments | 16 / 16 / 8 × 511 bytes |
| Trigger WHERE text / TIMEOUT / RETRIES | 4096 bytes / 1..60000 ms / 0..8 |
| View branches | 8 |
| Lock timeout | 1..3600000 ms (default 5000) |
| Bindings | 64 |
| Watch DURATION / DEBOUNCE | 1..3600000 ms / 1..5000 ms |

## 27. Diagnostics and error conditions

Diagnostics are `command: message` on stderr. Representative conditions:

| Condition | Status |
|---|---|
| unknown keyword/identifier/function, missing WHERE/ALL scope, bad literal, unterminated quote | 2 |
| type mismatch, cardinality/NOT NULL violation, record exists, path doesn't match schema | 4 |
| unmanaged entry in a record being deleted, unmatched entry (UNMATCHED ERROR) | 4 |
| dependency RESTRICT, transaction conflict, read-only transaction write | 4 |
| `..` component | 4 |
| missing table/directory, symlinked table directory, lock timeout, unwritable directory, ENOSPC/EFBIG | 3 |
| permission preflight failure (`directory of X is not writable … nothing committed`) | 3 |
| REQUIRE MATCH with no rows | 5 |
| decision durable but apply interrupted | 6 |
| CASCADE, transactional trigger DDL, streamed value with RETURNING, … (section 29) | 7 |

Before any decision is written, a write checks that every directory it will modify is writable
(permission preflight) and that the batch fits; failures in that phase are status 3 with nothing
committed. After the durable decision, failures are status 6 and `recover … APPLY` completes the work.

## 28. Durability, concurrency and crash behaviour

* Every write is a redo journal: payload staged in `.sql-journal.<txid>/`, manifest fsynced, the
  decision written and fsynced, then applied with renames, then DONE and reclamation. Maps are updated
  with UpdateMap plus checked `MS_SYNC`/fsync.
* A table is locked with `flock` (shared for reads, exclusive for writes) up to the lock timeout.
  Concurrent autocommit writers serialise; readers never see a partially applied write (they wait or
  return 6).
* Explicit transactions conflict at table granularity: the first committer wins; the second COMMIT
  returns 4 and must ROLLBACK and retry.
* A crashed autocommit command is retained in its context. The owner (same shell) runs
  `sql context "RESUME '<handle>'"` and `sql recover "TABLE '<t>' ALL APPLY"`; an undecided command is
  discarded, a decided one is completed. CLEAN STALE never deletes recoverable work.
* Raw filesystem writers are not transactional: SQL detects and validates their results but cannot
  isolate them. NFS and cross-device trees are not supported (EXDEV is refused before the decision).
* Test hooks (not for production): `SQL_TEST_CRASH=<point>` exits at a named boundary,
  `SQL_TEST_FAIL=payload-enospc|manifest-enospc` injects ENOSPC, `SQL_FANOUT_DEBUG=1` reports deferred
  notices, `SQL_TEST_WATCH_OVERFLOW` simulates inotify overflow.

## 29. Unsupported forms (status 7) and design decisions

Status 7, nothing changed: `CASCADE` on DROP; TRIGGER DDL inside a transaction; `ALTER TABLE ADOPT IDS`
inside a transaction; LINKED / BRANCHES view DDL inside a transaction; `RECOVER TABLE … TRANSACTION`;
`SET TYPE` across implicit file extensions without MATCH; RETURNING with a streamed FILE value;
computed/collection/capture projections in LINKED views; `RETURNING` with a streamed value.

Not provided at all: JOIN, UNION, GROUP BY, subqueries, IN/LIKE, arithmetic expressions, ORDER BY
alias, multi-key ORDER BY.

Design decisions: RESTRICT-only dependency policy; DROP INCLUDING DATA
removes managed entries only; dependency entries are lazily pruned intentions; trigger WHERE uses the
committed state at delivery; cross-table notices are eventual; linked-view generations auto-pruned
(keep 8, 60 s grace); transaction conflicts are table-granular; STRICT is opt-in; autocommit command
history is retained as full copies in the context.

## See also

`sql(1)` (summary man page), `TRANSACTIONS.md`, `VIEWS.md`, `MULTI_VIEWS.md`,
and the [language reference](filesystem-sql-language-reference.md).
