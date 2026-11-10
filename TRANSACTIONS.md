# Implemented contexts and transactions (development milestone)

> **Update 2026-11-09:** see MANUAL.md §18–20. CREATE/DEFINE/DROP/ALTER and saved-view DDL are staged in transactions; conflicts are table-granular (first committer wins, second COMMIT → 4); a permission preflight runs before the decision (status 3, nothing committed); the autocommit workspace `<cwd>/.context/<ppid>` is a full context usable by BEGIN, so `CONTEXT CREATE` there reports a PID workspace collision (status 4).


This describes tested current grammar, not the whole target contract. Typed views participate in staged reads, but view dependency registration/DDL transactions, TRIGGER/WATCH, mutation RETURNING and transactional DDL are still unfinished. Central context directories, full active command capture, RESUME and same-filesystem payload adoption are now implemented within the bounds below. Nothing below makes the unit FULL.

## Exact current grammar

```text
sql context 'CREATE [ON root] [OWNER live-same-UID-pid]'
sql context 'SHOW [context-path]'
sql context 'SET [context-path] TraceLevel|TRACE|LockTimeout|LOCK_TIMEOUT|Output = value'
sql context 'CLOSE [context-path]'
sql context 'CLEAN STALE ON root'
sql context 'INSPECT context-path'
sql context 'RESUME context-path [OWNER live-same-UID-pid]'
sql context 'MIGRATE legacy-.context_PID-file'
sql show 'CONTEXTS ON root'
sql show 'TRANSACTIONS ON root'
sql begin 'READ ONLY|READ WRITE [ON root] [CONTEXT context-path]'
sql commit '[CONTEXT context-path] [RETURNING TRANSACTION]'
sql rollback '[CONTEXT context-path]'
sql recover 'TABLE [table-path] ALL [REPORT ONLY|APPLY]'
sql recover 'DATABASE [root] ALL|TRANSACTION 32hexid [REPORT ONLY|APPLY]'
```

READ WRITE is default. Context creation prints its absolute handle followed by newline. SHOW emits one JSON object; ordinary BEGIN/COMMIT/ROLLBACK are quiet. COMMIT RETURNING TRANSACTION emits a JSON object with the ID and `"outcome":"committed"`. RECOVER defaults to report-only. Use DATABASE for coordinated participants; independent TABLE APPLY is refused.

Common `--context path` precedes the SQL statement. SQL_Options.context and SQL_CONTEXT are equivalent explicit sources; conflicting handles fail. Without one, only `.context/<getppid()>/.state` below exact invocation CWD is tried. BEGIN ON can derive that exact owner's context in its explicit root. No ancestor search, last-context fallback or implicit provisioning exists. A context never supplies an omitted table target.

For explicit `CONTEXT CREATE` only, `ON root` wins over `DATABASE_DIR`, including `ON '.'` for exact invocation CWD. Without ON, a nonempty `DATABASE_DIR` is required; absent/empty values fail before provisioning, with **no CWD fallback**. Environment contents are a literal path (spaces and shell-looking characters are not evaluated/expanded); relative values resolve against invocation CWD (`SQL_Options.cwd` for API calls), using existing safe path rules. The chosen root must already exist. This does not redirect table targets, change SQL_CONTEXT selection, provision BEGIN, or change automatic-write/watcher workspace policies, which already pass explicit roots.

CREATE explicitly provisions `.sql-root`, private `.context/<pid>/`, `.state` and `tables/`. OWNER defaults to getppid; use OWNER $$ in command substitution. Existing PID workspaces are never overwritten, including prior-boot collisions. Full ancestor PID/parent/UID/start records (maximum 128, overflow rejected) are saved with UID/owner start/boot/nonce. Both normal implicit/explicit handles independently validate the saved chain; reparenting requires explicit RESUME, not silent opt-in. Same-UID descendants may use a valid explicit handle; this is not cross-account permission.

RESUME validates same-UID ownership, resolves durable global/local outcomes without executing the saved SQL, preserves undecided staged data, and uses a synced `.rebind` proof, no-overwrite directory move and state update. A live different owner cannot be stolen. Pending rebinds require explicit completion; a proven dead/prior-boot rebind target may be explicitly adopted by a new owner. Previous owner identity is retained. INSPECT deliberately exposes sensitive saved text and bindings; default listings do not. SHOW TRANSACTIONS lists coordinator outcomes and active workspaces. CLOSE requires resolved idle state. CLEAN STALE preserves busy leases, non-idle work and incomplete/uncertain commands; it never auto-commits undecided data.

MIGRATE is explicit conversion of the older physical-v3 `.context_PID` file and sibling staging tree. It validates old slots, copies full owned pending data into the new workspace, publishes without overwrite and archives the exact old map as `.legacy-state`; the old sibling stage is retained conservatively. Missing source data/collisions fail without discarding it. Legacy local pending journals remain recoverable in the migrated stage; they are not silently dropped. There is no silent reinterpretation of old standalone files.

## Mapped format and mem tool

`.context/<pid>/.state` is physical v4: stable Trace header plus two page-separated sequence/checksum slots containing bounded pointer-free v3 payloads. Actual Map/UpdateMap is followed by checked MS_SYNC, file fsync and directory fsync. Zero mappings are not usable; constructors provision explicitly. Full active command bounds: SQL text <65536 bytes, <=64 bindings with aggregate value bytes <=65536, <=64 immutable FILE captures of <=64 MiB each. Effective default output/lock timeout and original cwd are retained. The exact verb plus one SQL text argument and length-delimited typed bindings is canonical invocation semantics; lossy argv joining remains refused.

Command phases are NONE=0 (offline draft), ACCEPTED=1, EXECUTING=2, COMMIT_DECIDED=3, APPLIED=4, FAILED=5. Accepted metadata precedes payload capture; executing precedes logical effects. `inputs/<sequence>/` owns exact synced bytes and identities; tokens for current execution read those copies. `tables/<slot>/` owns complete pending table/record/field images, not source-path recipes. Latest captured-input identities/size/fingerprint are checked before undecided commit/resume. Private ordinary `.command-local` proofs bind active command sequence/semantics to local journal outcomes even after a torn map slot. They are not additional mapped formats or executable queries. Corrupt proofs fail closed.

`sql_ctxmem handle` (also `sql_contextmem`) dumps a replayable shell script. TraceLevel, LockTimeout and Output are individual actual mio assignments; owner, boot, nonce, transaction and participant identity/generations are read-only descriptor fields/comments. LockTimeout is 1..3600000 milliseconds; Output is JSON=0, LINES=1, NUL=2, RAW=3. Retained mappings save/rebind the actual sys TracePointer to their shared mapped word and restore the previous pointer before unmapping. The active table/view scope overrides context scope; masks are not ORed/copied. Context Trace points at stable header LiveTraceLevel (TraceVersion 1), never a switchable slot/copy. Trace-only admin writes use actual mio conversion, atomic aligned writes, UpdateMap/MS_SYNC/fsync and preserve inode/logical generation. Long-running mappings observe them immediately. Transactional relations retain original definition locks/maps for live Trace while reading staged data/schema; commit merges the current physical word so a stage cannot revert live Trace or cause a false logical write. Mutable fields reject malformed/range-overflow values before Input_Memory_Item. Identity/state cannot be edited to bypass logical constraints.

LineageVersion=2 accompanies the full persisted ancestor array; each element and its count are actual read-only mio descriptors. Legacy migration captures a fresh chain only when old boot/UID/start identity still matches; otherwise explicit RESUME is required. Unknown versions and oversized chains fail.

State: 0 idle, 1 active, 2 committing. Outcome: 0 none, 1 committed, 2 rolled back, 3 conflict. A torn/invalid newest slot can fall back to a valid previous slot, but ACTIVE/COMMITTING sessions consult the durable global outcome before allowing more writes. Two invalid slots fail closed. Checksums detect accidental corruption; this is not protection against malicious same-UID modification.

## Staged execution

BEGIN makes a private stage. First access to each table/view records its canonical path, device/inode and generation and makes a durable streaming snapshot. Same-session operations route to it; other sessions see original data. Complete new field bytes, record images, symlinks and local journal payloads are context-owned durable files, not hashes/source path references. Successful staged writes synchronize data/journals/directories before return. FILE bytes remain correct if the original input is changed or deleted before COMMIT. A kill after a staged local decision can be reconciled by explicit RESUME, or explicit staged TABLE recovery; originals remain unchanged until global commit. Repeated reads use the staged snapshot, not a refreshed original. Current table/view participation is capped at 16, within one coordinator; overlapping table roots are refused. READ ONLY rejects writes.

Counts and NOT NULL are deferred within an explicit transaction and validated across the complete final staged tree at COMMIT. A failing constraint leaves originals untouched and permits repair or rollback. Autocommit validates final structural counts on a private skeleton before a commit decision; no original payload hardlinks or chmod are used. INSERT/UPDATE still validate assigned scalar/file values before staging.

No flock is held by an exiting CLI process. Each operation locks its context, and commit locks the coordinator and sorted participant tables, checks identities/generations and constraints, then writes a global durable COMMIT decision. Prepared participant journals hold readers at status 6 until the global DONE is durable. Applying can expose partial paths to raw filesystem tools, but not to a cooperating SQL reader. No cross-database, NFS, distributed or arbitrary external-writer isolation is claimed.

A generation conflict returns 4, keeps the stage and does not change originals. Roll back and retry against fresh data. Uncooperative edits to existing payload bytes without a generation change are not detected. Context-file locks serialize simultaneous calls in one session. Independent sessions race safely at commit; the stale generation cannot silently overwrite a winner.

## Outcomes, recovery, and reclamation

A global decision is authoritative. Predecision failure/kill can be aborted; after durable COMMIT, recovery only finishes it. A status 6 is not proof of rollback. ROLLBACK refuses unresolved committing work. Repeated COMMIT can recover its own interrupted decision. DATABASE APPLY is idempotent, and DONE/ABORT manifests remain as outcome proofs. An owner surviving a crash before its context acknowledgment reconciles the known outcome on next access.

Completed local journals are atomically renamed from `.sql-txn.UUID` to `.sql-clean.UUID` and the directory fsynced before any redo payload is deleted. A root-device/inode/owner/ID proof survives until all children are removed. Recovery reclaims retired journals without replaying a partially deleted manifest/payload set. Nonempty unproven/foreign directories are preserved. Only the proven private engine journal/staging namespaces are recursively reclaimed, never arbitrary table payloads. Recovery may remove an unproven retired directory only with nonrecursive rmdir after confirming it is empty.

## Current limits that still matter

- Transaction CREATE/DEFINE/DROP and view Query mem edits are explicitly refused. Full schema ALTER, view dependencies and cross-table shared anchors are pending.
- Attached provisioned contexts retain the active command, not a complete command history. Normal context-free autocommits retain ordinary redo but do not automatically provision a persistent command workspace.
- Commit retains a hardlink to each adopted staged inode inside redo, then atomically renames a journal-local installation link into the destination; retained replay sources survive repeat apply. This is per-file adoption, not one globally atomic row-directory rename. Cross-device sources/root/destination components are refused predecision; same-device bind-mount edge cases and hostile path replacement are not exhaustively tested.
- Snapshots refuse FIFOs/devices/sockets, without opening them. Autocommit metadata-only reads can inspect those entries; deep content validation and ordinary writes can reject them.
- Snapshots stream copying, but current value/query payload reads are <=64 MiB; result rows <=65536. This is not complete large-video streaming support.
- Replacements currently get private 0600 permissions and commit-time mtime. Unchanged files remain intact. Full metadata-preserving update semantics are pending.
- Snapshot copies can consume substantial disk space. Audit manifests accumulate; there is no automatic audit GC yet.
- Linux /proc identities and local filesystem fsync/flock/renameat2 semantics are required. Writable ancestors and hostile same-UID races remain outside the tested threat model.
- The test matrix covers selected decision/application/reclamation crashes and real file-size-limit failures, not every fsync failure or a physical disk-full campaign. Trigger external delivery is not implemented; no exactly-once outside-action claim is made.

## Existing sys lineage integration and source limitations

The actual guardian `sys/lineage.c` and RTP/call consumers were inspected. `lineage()` compares cached ancestry within one process, not generic PID existence; its first call returns 1, it uses 32-element globals without bounds checks, and its whitespace `/proc/stat` split mishandles comm containing spaces. SQL never modifies that unit. SQL's own parser reads through the final `)` and validates PID, UID, state, parent and start time; zombie/dead owners are rejected. An ancestry walk is bounded at 128 processes and compares every PID/start identity.

For short (<=28), no-whitespace chains, implicit applicability additionally exercises real sys lineage twice in a short-lived isolated child, with a two-second alarm and independent before/after fingerprint checks. Its globals/sticky cache cannot corrupt an embedding caller's cache. Deep/space-containing chains use the bounded parser rather than the unsafe legacy path. Explicit library context handles avoid the legacy sys probe but still validate every persisted ancestor; embeddings must coordinate SIGCHLD reaping/legacy global use. No cached first return drives cleanup. Tests cover all these cases and preserve a mapped descendant even after its owner exits.

## Mem command-draft replay

`sql_ctxmem workspace` prints individually quoted configuration assignments, read-only lineage/phase/input identity comments and `--offline C.Command.Variable value` assignments for text, typed binding bytes and effective options. Offline edits require a resolved idle workspace and always create phase NONE; identity/phase/journal fields cannot be forged. Replay never executes SQL, commits staged data, or recreates captured input identities. Scripts for active/unresolved contexts therefore refuse offline replay until resolved; they are still inspectable. Treat the full dump as sensitive.
