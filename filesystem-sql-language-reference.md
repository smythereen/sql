# Filesystem SQL — first-build language reference

> **Note 2026-11-09:** this is the original design target. The implemented, verified grammar is in MANUAL.md; where they differ, MANUAL.md is authoritative.


Status: **target language contract**, not a claim that every feature below is operational. See [MANUAL.md](MANUAL.md) for the tested, implemented grammar and explicit gaps.

Architecture updated by John on November 7, 2026: **20 command entry points through one `sql` multicall executable**, with `sql_select`-style invocation aliases. `sql.c` dispatches only. Each `SQL_Select(...)`-style public operation has its own source/object file in `libsql.a`; shared parser/storage helpers remain separate objects. Every implemented mapped format has a corresponding `sql_*mem` tool.

## Conceptual model

A table is a filesystem directory. A record is a directory in its declared structure, and each field member is a file in the record directory. `.table` and `.view` are map-unit definition files. `.context/<pid>/.state` map-unit files inside context workspaces store session and transaction context, not an alternative implicit table.

Scalar types include TEXT, INT64, UINT64, and BOOL. OCTETS preserves arbitrary bytes; JPG, MP4, SH, and other format types describe and constrain file contents. An extension is not proof of format. SH fields are **never automatically executed** by selection, insertion, linking, or inspection.

Fields can contain multiple files: `[1-4]` means one through four members, `[0-]` zero or more, `[1-]` one or more, and `[0-1]` zero or one. An unqualified field has exactly one member. Count actual members, not the highest suffix; deleting a member must not renumber the others. Zero members, an empty file, and SQL NULL are different. NULL requires explicit metadata, not merely an absent file. NOT NULL and cardinality are separate constraints, checked on the completed record at commit.

Nested DIRECTORY declarations describe groups; RECORD explicitly marks the record boundary rather than inferring it from depth. FORMAT uses checked printf conversions to generate names, including literal prefixes such as `"my_%04.4u"`. MATCH recognizes an entire path component using a regex, for example `".*_([12][0-9][0-9][0-9])"`. CAPTURE assigns names and types to groups. Calendar validity needs additional checks. Names and capture tokens are case-sensitive, so month and minute remain distinct.

Symbolic fields intentionally share content. Stable shared-value anchors, reverse references, and immutable record IDs are a **proposed mechanism, not a finalized canonical layout**. Updating shared content affects all references, validates all affected records, and fans out committed events. Unlinking makes a private copy; it does not delete the value. Renames and deletions must respect dependencies.

Table-based triggers consume committed change events, not arbitrary temporary filesystem notifications. Integration with the existing trigger unit is intended; no specific existing trigger/map APIs are asserted here. Delivery is at least once, with event IDs for deduplication.

First build includes shared symbolic fields, file formats, nested schemas, member cardinalities, ORDER BY, LIMIT, and OFFSET. Joins, cross-record aggregation, indexes, automatic cascading deletes, and cross-database transactions are deferred. Collection COUNT is included, not general cross-record aggregation.

## Accepted implied-table rule

**Where a table operand is optional, omission means the exact invocation current working directory (`getcwd()`).**

- Never search ancestors. A record directory without its own required `.table` is not an implied table; give a helpful error.
- A context chooses a session, never another implicit table.
- Resolve supplied relative paths against invocation CWD. Retain checked target identity, locks, and stable directory-file-descriptor-relative access rather than repeatedly resolving mutable paths.
- Validate the local `.table` or `.view` appropriate to the command. Views are read-only. Unknown directories are not implicitly created or adopted.
- TABLE and VIEW remain required discriminators where shown; their path may be omitted.
- CREATE can use CWD only if safe: no overwritten definition or silent adoption of unknown contents. DEFINE validates existing data before installing metadata, without renaming or rewriting it.
- Missing target does not authorize unfiltered mutation. Missing WHERE on destructive record/member operations is an error unless an explicit applicable ALL scope is present.

Equivalent SELECT forms:

```bash
sql_select title WHERE 'rating >= 4'
sql_select title FROM . WHERE 'rating >= 4'
```

`sql_insert INTO . ...` and `sql_insert ...` also target the same CWD table. `sql_describe TABLE` and `sql_check TABLE` use CWD. `sql_drop` still requires TABLE or VIEW; omitting its path does not authorize deleting data.

## Grammar conventions

Uppercase words denote clauses; lowercase names are supplied values. `[optional clause]` below indicates grammar optionality, whereas numeric `[1-4]` inside a schema means cardinality. SQL keywords are case-insensitive; logical names, filesystem names, capture names, and format tokens are case-sensitive. Prefer portable logical identifiers.

One statement per invocation; final semicolon optional. Quote schemas and expressions so Bash does not expand brackets, braces, redirections, or parentheses. Typed bindings are preferable to concatenating dynamic values into SQL. Their exact CLI spelling remains to be specified. Projection expressions are required: request `*` explicitly rather than guessing an omitted projection.

## The 20 command entry points and their target clauses

This is the approved first-build outline expanded with optional-target rules and proposed safe defaults. Collection mutation and link endpoint spellings below remain design details to finalize, not implemented grammar.

### 1. `sql_create` — Create a new definition and filesystem structure

- `TABLE [path] (...)` — Declare a table rooted at the supplied directory, or exact CWD.
- `VIEW [path] AS SELECT ...` — Declare a read-only saved query. Path defaults to CWD; resolve and persist source scope so later invocation CWD cannot silently retarget the saved query.
- `DIRECTORY (...)` — Declare nested directory groups.
- `RECORD` — Explicitly mark which directory level represents a record.
- `FORMAT "..."` — Generate names using checked printf conversions.
- `MATCH "..."` — Match an entire directory or filename using a regex.
- `CAPTURE (...)` — Name and type values extracted from matching names.
- `field type [minimum-maximum]` — Declare scalar or file-format fields and member counts.
- `NOT NULL` — Prohibit a NULL value, separate from collection cardinality.
- `DEFAULT value` — Supply a value when insertion omits the field.
- Required: object-kind discriminator and definition. No implicit overwrite or adoption.

### 2. `sql_define` — Apply the same declaration to existing directories

- `TABLE [path] (...)` — Same structure, types, naming, and count clauses as CREATE; path defaults to CWD.
- `VALIDATE ONLY` — Report compatibility without installing `.table`.
- `UNMATCHED ERROR | IGNORE` — Reject unmatched entries by default, or explicitly leave them outside the table.
- `LINKS INTERNAL | REJECT` — Validate supported internal symbolic fields or reject links; never silently follow arbitrary targets.
- Proposed default: LINKS REJECT; explicitly opt into validated existing sharing. Never rewrite existing data during DEFINE.

### 3. `sql_describe` — Explain a definition

- `TABLE [path]` / `VIEW [path]` — Select definition; discriminator required, path defaults to CWD.
- `FIELD field-path` — Describe one nested field.
- `INCLUDING REFERENCES` — Show shared-value references and dependent definitions.
- `AS DDL` — Print a reusable declaration.
- Without detail clauses, describe the whole definition, without expanding references.

### 4. `sql_show` — List database objects and activity

- `TABLES IN root` / `VIEWS IN root` — List registered definitions in checked coordinator scope.
- `CONTEXTS` — List accessible sessions.
- `TRANSACTIONS [STATE state]` — List transactions, optionally filtered by state; omission means all accessible states in scope.
- `TRANSACTION id` — Report one transaction's outcome.
- `TRIGGERS [ON table]` — List trigger registrations; omitted table means CWD table, not every table.
- Object category is required; root omission follows coordinator rules below, not a recursive directory search.

### 5. `sql_select` — Read logical values and filesystem information

- `projection-list` — Required fields, captures, PATH(...), CONTENT(...), or filesystem metadata; `*` is explicit.
- `[FROM table-or-view]` — Source; omission means exact CWD.
- `WHERE expression` — Comparisons, NULL tests, Boolean expressions, ANY, ALL, and collection counts. Omitted means all records, read-only.
- `ORDER BY expression [ASC | DESC]` — Sort results; direction defaults to ASC. Without ORDER BY, order is unspecified. Equal keys need an explicitly unique tie-breaker for stable ordering.
- `LIMIT count` — Bound output rows; omitted means unbounded.
- `OFFSET count` — Skip output rows after ordering; default zero. LIMIT/OFFSET require nonnegative typed integers.
- `OUTPUT JSON | LINES | NUL | RAW` — Structured, text, pathname-safe, or single-value binary output. Proposed default JSON; precise framing still to specify, not silently JSONL.
- `REQUIRE MATCH` — Distinct failure status for no matches; without it, empty results succeed.
- RAW requires one projected field member and exactly one matching output value, never implicit binary concatenation. LINES/NUL are explicit.

### 6. `sql_insert` — Create records or add collection members

- `[INTO table]` — Destination; omission means CWD table.
- `RECORD name` — Supply record name when not generated from captures.
- `(field-list) VALUES (...)` — Assign initial values, including captured naming values.
- `FILE(path)` — Import bytes without executing the file.
- `ADD TO collection VALUES (...)` — Add members to existing records.
- `WHERE expression` — Select destination records only in ADD TO mode.
- `ALL RECORDS` — Proposed explicit authorization for unfiltered ADD TO; without WHERE or this scope, adding to existing records fails.
- `RETURNING projection-list` — Return generated IDs, paths, or values.
- VALUES and relevant field destinations are required. Omitted fields use declared defaults or must otherwise satisfy NULL/cardinality constraints. No implicit overwrite/upsert.

### 7. `sql_update` — Modify selected values

- `[table]` — Target; omission means CWD table.
- `SET field = value, ...` — Required assignments; FILE(path) replaces content.
- `WHERE expression` — Identify records or collection members.
- `ALL RECORDS` — Explicit authorization for an unfiltered record update.
- `ALL MEMBERS` — Proposed explicit scope for an unfiltered collection-member operation; collection must be identified unambiguously.
- `RETURNING projection-list` — Return resulting values or paths.
- Missing WHERE without an applicable explicit ALL scope is an error. Shared fields retain sharing: updates change the common value and validate all affected references.

### 8. `sql_delete` — Remove records or collection members

- `[FROM table]` — Target; omission means CWD table.
- `MEMBERS collection` — Proposed collection-member deletion target instead of records.
- `WHERE expression` — Identify records or collection members to remove.
- `ALL RECORDS` / `ALL MEMBERS` — Explicit unfiltered removal at the corresponding scope; never inferred from missing WHERE.
- `RETURNING projection-list` — Return selected pre-deletion information.
- Enforce minimum counts and reference rules at commit. No automatic cascade. Final member-target grammar must prevent omitted arguments from changing member deletion into record deletion.

### 9. `sql_link` — Share content through symbolic links

- `[FROM table]` — Destination table; omission means CWD.
- `FIELD field-or-member` — Destination field/member.
- `TO source-field-or-member FROM SOURCE source-table` — Proposed explicitly qualified source endpoint. Source table and member identity must be explicit until final syntax is agreed; never default both endpoints.
- `WHERE expression` — Select destination records/members, not source identity.
- `ALL RECORDS` / `ALL MEMBERS` — Proposed explicit unfiltered destination scope.
- `RETURNING projection-list` — Return resulting paths/reference identities.
- Validate types, counts, dependencies, and permitted targets. Require unambiguous source cardinality; no accidental many-to-many sharing.

### 10. `sql_unlink` — Make a shared member private

- `[FROM table]` — Destination table; omission means CWD.
- `FIELD field-or-member` — Shared member to detach.
- `WHERE expression` — Identify affected records/members.
- `ALL RECORDS` / `ALL MEMBERS` — Proposed explicit unfiltered scope.
- `RETURNING projection-list` — Return resulting paths/values.
- Materialize current content as a private copy; do not delete the field/shared value. Missing WHERE without explicit scope fails.

### 11. `sql_alter` — Change definitions or rename managed objects

- `TABLE [path]` — Table; omitted path means CWD.
- `ADD FIELD definition` — Add a field with type, naming, and count constraints.
- `ALTER FIELD field definition` — Change a definition after validating existing data.
- `DROP FIELD field` — Remove a field definition, subject to dependencies.
- `RENAME FIELD old TO new` — Rename a logical field and managed files where required.
- `RENAME RECORD old TO new` — Rename a record directory while preserving its internal ID.
- `VALIDATE ONLY` — Report consequences without applying changes.
- An explicit alteration is required. Before implementation, distinguish definition removal from purging field bytes; never silently equate them or rewrite unspecified content.

### 12. `sql_drop` — Remove a registered definition

- `TABLE [path]` / `VIEW [path]` — Required discriminator, optional path defaulting to CWD.
- `RESTRICT` — Refuse removal when dependencies exist; default.
- `INCLUDING DATA` — Explicitly request managed table data deletion as well as definition removal.
- `VALIDATE ONLY` — Report dependencies/affected paths without changing them.
- Default preserves data. CWD targeting does not make DROP harmless. No implicit cascade, guessed object kind, or deletion of unmatched/unrelated files. Dropping a view never deletes its sources.

### 13. `sql_begin` — Start a transaction

- `READ ONLY | READ WRITE` — Access mode; proposed default READ WRITE.
- `ON database-root` — Coordinator and transaction scope; checked-root rules below apply.
- `CONTEXT context` — Explicit mapped session; otherwise validated derived session.
- Nested BEGIN is rejected. Without BEGIN, individual mutations autocommit atomically.

### 14. `sql_commit` — Commit the active transaction

- `CONTEXT context` — Session; omitted means validated derived session.
- `RETURNING TRANSACTION` — Report ID and durable outcome.
- Active transaction required. Conflicts/validation failures prevent commit; uncertain storage outcomes are reported distinctly. No RETURNING means no normal stdout payload.

### 15. `sql_rollback` — Discard uncommitted work

- `CONTEXT context` — Session; omitted means validated derived session.
- Active uncommitted transaction required. Committed transactions cannot be rolled back.

### 16. `sql_context` — Manage `.context_{pid}` mapped sessions

- `CREATE [ON database-root] [OWNER pid]` — Initialize a session with checked owner identity. Explicit ON wins over DATABASE_DIR; ON `'.'` explicitly selects invocation CWD. Omitted ON requires nonempty DATABASE_DIR; no CWD fallback. Its value is a literal path, relative to invocation CWD when not absolute. This default applies only to explicit CONTEXT CREATE, not table targeting, SQL_CONTEXT selection, BEGIN provisioning or automatic-write/watcher workspace policies.
- `SHOW [context]` — Inspect settings/transaction state; omitted handle means derived session.
- `SET [context] option = value` — Change supported settings; same default session.
- `CLOSE [context]` — Close an idle session; refuse unresolved transactions.
- `CLEAN STALE` — Reclaim verified dead sessions after resolving their journals.
- Subcommand required. OUTPUT and LOCK_TIMEOUT are proposed setting categories; final allowlist/bounds remain to specify. Closing never implicitly commits/rolls back. Cleanup requires explicit scope and verified ownership, not a PID filename sweep.

### 17. `sql_trigger` — Manage explicit trigger registrations

- `CREATE name [ON table]` — Register on a table; omitted table means CWD.
- `AFTER INSERT | UPDATE | DELETE | LINK | UNLINK` — Required committed event selection, not implicit every-event registration.
- `OF field-list` — Restrict fields; omitted means any field for selected events.
- `WHERE expression` — Event filter; omitted means no additional filtering.
- `EXECUTE executable ARGUMENTS (...)` — Required program and explicit argument list, never an implicitly evaluated shell string. Empty arguments permitted.
- `TIMEOUT duration` / `RETRIES count` — Bounded execution/retries; finite timeout and retry limits must be documented before implementation, without an invented numeric default here.
- `ENABLE name` / `DISABLE name` / `DROP name` — Manage a registration in the selected table scope.
- Proposed creation default: disabled until explicit ENABLE, avoiding surprise external execution. SH content is never implicitly executed.

### 18. `sql_watch` — Consume committed events through trigger integration

- `ON database-root` — Event source under checked coordinator rules.
- `FOR trigger-list | ALL` — Require explicit registration selection, not silently all triggers.
- `ONCE | CONTINUOUS` — Drain available events or keep watching; proposed default CONTINUOUS for the explicitly invoked watcher.
- `RESUME` — Continue durable checkpoints; default, not replay all history.
- At-least-once delivery includes event IDs for deduplication. Starting a watcher does not enable disabled registrations.

### 19. `sql_check` — Inspect consistency without repair

- `TABLE [path] | DATABASE root` — Scope; omitted TABLE path means exact CWD. DATABASE follows coordinator rules.
- `SCHEMA | NAMES | COUNTS | TYPES | LINKS | JOURNALS | ALL` — Check selection; proposed default ALL.
- `DEEP` — More expensive supported content-format validation; opt-in.
- `WHERE expression` — Limit record-level checks, without claiming a full database check afterward.
- Always nonrepairing; ordinary checks do not imply deep validation.

### 20. `sql_recover` — Resolve interrupted operations

- `DATABASE root` — Checked coordinator scope.
- `TRANSACTION id | ALL` — Required explicit work selection.
- `REPORT ONLY` — Explain recovery without changes; proposed safe default.
- `APPLY` — Proposed explicit authorization to perform recovery rather than mutate by omission.
- Discard undecided abandoned work and finish durably committed work. Never guess or discard a committed transaction. Manual selection does not override durable decisions.

## Other optional arguments: proposed initial defaults

The exact-CWD rule and explicit unfiltered-mutation authorization are accepted requirements. The following defaults fill in the design; choices not already agreed remain recommendations.

| Omission | Default / rule |
|---|---|
| Omittable table operand | Exact invocation CWD, validated locally; no ancestor search. |
| Required discriminator, projection, SET, schema, source endpoint, subcommand | Error, not a guessed operation. |
| SELECT WHERE | All records, read-only. |
| Mutation WHERE | Error unless explicit applicable ALL RECORDS / ALL MEMBERS. |
| RETURNING | Quiet success: no result payload or unsolicited counts on stdout. Errors/diagnostics go to stderr. |
| ORDER BY / LIMIT / OFFSET | Unspecified order / unbounded / zero. |
| OUTPUT | JSON, with framing to specify; LINES, NUL, RAW explicit. |
| REQUIRE MATCH | Empty SELECT succeeds. |
| Cardinality | Exactly one member. |
| NOT NULL | NULL may be permitted subject to type/schema; cardinality still applies. |
| DEFAULT | No invented value; satisfy presence/NULL constraints or fail. |
| FORMAT / MATCH / CAPTURE | Fixed declared names need no naming clauses; no inferred capture names. |
| BEGIN | Per-command atomic autocommit. |
| Context | Validated derived session, never a table override. |
| BEGIN mode | READ WRITE. |
| Lock timeout | Finite configurable bound; numeric value to finalize. |
| DROP INCLUDING DATA | Preserve data; RESTRICT dependencies. |
| CHECK selector | ALL, nonrepairing; DEEP opt-in. |
| RECOVER action | REPORT ONLY; APPLY explicit. |
| Trigger creation state | Disabled until explicit ENABLE. |
| Watch mode / position | CONTINUOUS / RESUME; explicit trigger scope. |

FORMAT and MATCH may be independent. MATCH-only insertion requires a concrete supplied matching name. With both, generated names must match. A derived default matcher for simple FORMAT-only definitions is a possible convenience, not a promised general printf-to-regex converter. Ambiguous/noninvertible naming needs explicit values/captures or fails. Formats and regexes are not shell code.

### Coordinator roots are different from table operands

BEGIN ON, context creation, WATCH ON, RECOVER DATABASE, database-scoped CHECK, and root-scoped SHOW need a coordinator, not merely a table. A missing root may use a checked active context's coordinator; otherwise require an explicit root. Exact CWD may supply it only if CWD independently validates as a coordinator root. Never search parents, assume every table is a coordinator, or initialize a coordinator implicitly. The coordinator metadata marker remains to design.

### Sessions, subshells, and execution options

The default external-command session derives from the invoking shell parent PID, verified with UID, process-start identity, boot ID, and a session nonce. PID alone is unsafe because of reuse. Platform start-identity details remain to implement.

Pipelines, command substitutions, and subshells may change parentage. Use an explicit checked context handle (proposed common `--context` or `SQL_CONTEXT`) to share a transaction across them. Conflicting/mismatched handles fail rather than silently switching sessions. Context maps select session/coordinator settings, never an alternate implicit table.

Common options cover typed bindings, context, lock timeout, and machine-readable diagnostics. Final spellings/precedence need a separate argv specification. Require an explicit discriminator/clause whenever positional omission would be ambiguous.

## Queries and filesystem metadata

```bash
sql_select 'PATH(image)' WHERE 'year = 2026 AND month = 7' OUTPUT NUL
sql_select 'PATH(image)' FROM /data/assets \
    WHERE 'ANY(image, fs.mode = 0o750)' OUTPUT NUL
sql_select 'PATH(image)' FROM /data/assets \
    WHERE 'COUNT(image) >= 2' ORDER BY year DESC LIMIT 20 OFFSET 0 OUTPUT JSON
```

Metadata properties include fs.owner, fs.group, fs.mode, fs.permissions, fs.mtime, fs.size_bytes, and fs.type. Codes include d (directory), f (regular file), l (link), s (socket), p (pipe), plus block/character devices. Default inspection is the directory entry itself; fs.target.type explicitly inspects a permitted resolved target. Broken/forbidden targets need defined errors/NULL metadata, not arbitrary traversal. Never open pipes, connect sockets, execute scripts, or read devices just to inspect metadata.

Octal is explicit: `0o750`, not decimal 750. Symbolic permissions use o=owner, g=group, w=world; this differs from chmod's o=others and must be documented. `IS 'o:rw-,g:rwx,w:..x'` requires specified bits, `-` means absent, and `.` means don't care. HAS requires supplied bits without forbidding unspecified ones.

ANY is a record-level collection predicate. Member predicates/captured times must have explicit member scope when selecting individual image paths; never treat an arbitrary member's hour as a record scalar. Final grammar must make expansion/filter scope unambiguous.

Use paths and NUL delimiters for arbitrary filenames:

```bash
while IFS= read -r -d '' image; do
    printf '%s\n' "$image"
done < <(sql_select 'PATH(image)' FROM /data/assets \
          WHERE 'year = 2026' OUTPUT NUL)
```

Avoid `for image in $(...)` for arbitrary filenames. CONTENT explicitly reads bytes; RAW is deliberate single-value binary output, not accidental MP4 output in a text loop.

## Safe-failure examples

- `sql_select title` in a record directory lacking its own definition fails, without looking above it.
- `sql_update SET ...` or `sql_delete` without WHERE/explicit scope fails even with an implicit CWD target.
- `sql_drop` without TABLE/VIEW fails. `sql_drop TABLE` targets CWD but preserves data unless INCLUDING DATA is explicit and checks pass.
- Missing link source fails; implicit destination does not imply source.
- Missing root fails unless a checked context or exact validated coordinator CWD supplies it.

## Documentation history and open decisions

Saved November 7, 2026 (America/New_York), from the approved 20-executable outline plus accepted exact-CWD and explicit-mutation-scope rules. This task creates documentation only: no repository creation, implementation, build, or guardian changes.

Finalize before implementation: collection mutation/link endpoint grammar; typed-binding argv syntax; JSON framing; NULL encoding; canonical record/member/shared-anchor layout; coordinator metadata/locking; validator coverage; crash-journal and trigger APIs; timeout/retry bounds; and definition-only field removal versus explicit data purging. These are proposed design details, not operational features.


## Implementation history

The earlier documentation-only history above records the original save, not the current unit status. A local C implementation now exists in the sql unit directory. The architecture was superseded by the multicall/per-operation-object decisions. Read [MANUAL.md](MANUAL.md) before using the target grammar: physical/multiquery linked views, trigger execution, dependencies, and other listed features remain unfinished; unsupported operations fail rather than report success.

## Accepted later context architecture (implemented milestone; see limits)

The context is to be a private directory `dbroot/.context/<pid>/`, not a standalone metadata map. It contains `.state` versioned mapped metadata (sql_ctxmem accepts the workspace directory), `tables/` staged table/record/field trees, the entire active SQL verb/text or lossless argv, typed binding names/types/lengths/values, bounded durable command phases and transaction/sequence identity, and complete context-owned pending table/record/field data. File inputs must be copied durably; a source path or hash alone is insufficient. Large values can live in owned staged files, not whole-blob mappings. Every introduced mapped format still requires a real mem decoder.

All staged files/directories and metadata must be synced before acknowledging command success. Interrupted contexts survive dead shells/new boot identities without automatic deletion. Explicit same-UID inspection/resumption must consult durable transaction outcomes before replay and must not duplicate committed operations or external events. An uncommitted context is never silently committed on a new login.

Commit should adopt/move same-filesystem staged replacement images under locks and a durable idempotent journal; cross-device work must fail before a decision, not silently copy. SQL readers stay gated across multi-rename apply; raw observers do not get atomic filesystem snapshots. Stage ownership and retained replay sources must survive partial application until all consumers complete. See [MANUAL.md](MANUAL.md) for actual current support and remaining gaps; the implementation now provides central directory workspaces, captured commands and per-file staged inode adoption, not a globally atomic filesystem snapshot.

The central `dbroot/.context/<pid>/` layout supersedes the earlier `.context-{pid}/` suggestion. Registry discovery/cleanup is rooted at `.context`; a reused PID from another boot/start/nonce must not overwrite an unresolved workspace. Require an explicit same-UID recovery/rebind/archive operation with stable journal references. This is now the installed workspace layout. Older standalone contexts require explicit validated MIGRATE; unresolved source data is preserved.

## Persisted ancestry and active invocation refinements

Each context stores the complete owner lineage, including PID, parent PID, UID and process-start identity for every saved ancestor, plus boot ID and owner/session nonce. The array is bounded with explicit overflow failure. Any independent process can validate the saved chain; sys lineage() first-call success or a per-process cache is insufficient. A changed/dead/prior-boot chain stops normal inheritance and does not authorize deleting pending data. Explicit same-UID RESUME updates ownership/lineage after consulting actual journal outcomes; it never automatically reruns saved SQL. The active canonical invocation contains verb, exact SQL text, typed bindings with byte lengths, effective options and original cwd. Limits and explicit input/draft behavior are in TRANSACTIONS.md.

## Accepted physical and multiquery linked views — required, NOT implemented yet

Beyond saved SELECT definitions, a view can be a table-shaped filesystem directory tree: record subdirectories and approved field symlinks expose data owned by source tables. SQL queries, including exact-CWD omitted FROM, use the same relational grammar. SQL mutations through the view are read-only/refused. Projection aliases/nested paths and stable source identities need explicit schemas; no copied payloads or arbitrary symlink traversal are implied.

A .view definition must accommodate multiple source queries, initially expressible as separate named output branches with stable record keys and explicit branch/path naming. Output path collisions are errors, never silent overwrites. Source identities, definitions/bindings and dependencies must be durable pointer-free metadata with an actual viewmem decoder. Source additions/deletions/filter changes/renames require coherent membership refresh before SQL returns, with source commit dirtiness/versioning, recovery gates and dependency restrictions. Raw filesystem observers may see the previous refreshed membership snapshot; symlinks alone do not make membership always live.

Multiquery support is required work, but general JOIN/UNION relationship/duplicate semantics have not been finalized or claimed. Current single-source typed saved-query views do not satisfy this new physical/multiquery requirement. Preserve both requirements rather than relabeling that implementation as complete.
