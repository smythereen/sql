# Typed saved views and bounded single-source LINKED views

> **Update 2026-11-09:** superseded in detail by MANUAL.md §17. Since this was written: a dependency registry exists (DROP/ALTER of sources is RESTRICTed while views exist; `SHOW DEPENDENTS OF`), linked generations are garbage-collected (auto keep 8 / 60 s grace; `ALTER VIEW … PRUNE GENERATIONS [KEEP n]`), `DROP VIEW … INCLUDING DATA` removes managed link trees, and saved-view DDL is transactional (LINKED DDL in a transaction remains status 7).


A VIEW is an otherwise-empty directory containing an exact-size pointer-free native `.view` map (magic/version/bytes/endian, TraceLevel, generation, pinned canonical source/device/inode, saved query). No existing content is overwritten. Every `.view` has `sql_viewmem`; it uses real Map/mio descriptors and checked synchronous durability, not JSON pretending to be a map.

```text
CREATE|DEFINE VIEW [directory] AS SELECT projection [FROM source] [WHERE ...] [ORDER BY ...] [LIMIT ...] [OFFSET ...]
DESCRIBE VIEW [directory] [AS DDL]
CHECK VIEW [directory]
DROP VIEW [directory] [VALIDATE ONLY]
SHOW VIEWS IN directory
```

CLI examples use one SQL argument: `sql create "VIEW '/tmp/db/titles' AS SELECT title AS label,age FROM '/tmp/db/assets'"`; `sql select "label FROM '/tmp/db/titles' WHERE age > 20 OUTPUT NUL"`.

Omitted FROM is exact invocation CWD at definition time and is saved canonically; not a context-selected table. Saved queries cannot specify OUTPUT. Outer queries choose framing. `AS alias` names exposed columns; simple identifiers default to their own names, computed columns to `column_N`. Ambiguous names fail before metadata creation. Sources may be tables or views; recursive execution is bounded to 16 and cycles fail. The pinned directory identity prevents replacement of a source path from silently retargeting a view.

Saved query results are materialized as typed scalar/collection Values, never converted through JSON strings. NULL, empty text/collections, binary and Boolean/integer types survive. Outer predicates, ANY/ALL/COUNT, CONTENT expansion, ordering and limits work on exposed columns after saved-query ordering/limits; no unsafe predicate pushdown changes semantics. Hidden source fields/captures/fs metadata do not leak into the outer schema. Project PATH/fs values under aliases when needed; PATH on virtual columns is refused.

Views are read-only. Mutation through a view returns constraint status 4. Explicit contexts snapshot view definitions and source tables, so reads see staged source updates and repeatable definitions; a concurrently replaced definition conflicts at commit. View DDL and Query mem edits during a transaction return 7. `sql_viewmem directory C.Query 'clauses FROM ...'` validates and pins its new query before durable replacement. Omitted FROM in that edit means tool-invocation CWD. Long Query values use bounded actual mio byte descriptors; dumps quote each TraceLevel/Query assignment separately and replay.

Trace scopes point at the shared original `.view` TraceLevel, including transactional reads, and restore their parent pointers before unmapping. Trace-only mem writes keep inode and definition generation, are visible without remapping, and are not rolled back by transaction commit.

## Not implemented / important safety limit

There is no persistent dependency registry yet. Plain DROP is definition-only and preserves all source/payload bytes, but can break dependent views. Explicit RESTRICT fails 7 instead of pretending to enforce dependencies. Do not use definition-only DROP as a verified dependency operation. Source deletion/renaming outside SQL also fails views safely rather than retargeting. Transaction-atomic view creation/drop and dependency-aware schema ALTER remain required before FULL completion.

## Single-source physical LINKED views — implemented bounded slice

```sh
sql create "VIEW '/tmp/adult-view' LINKED AS SELECT title AS label FROM '/tmp/assets' WHERE age >= 18"
cd /tmp/adult-view
sql select '*'                 # exact view CWD; typed read-only query
ls -l records                  # atomic pointer to the managed directory tree
cat records/a/label            # symlink to /tmp/assets/a/title; no copied payload
sql check 'VIEW'               # also refreshes directory membership
```

`LINKED` is explicit, so existing saved-query views keep their prior behavior. Linked definitions use `.view` version **2**, the same pointer-free size with read-only `reserved=1` as the LINKED flag; saved-only definitions remain version 1/reserved=0. `sql_viewmem` decodes both, displays the flag, and validates scalar projections on Query edits. TraceLevel still uses the original shared mapped word and existing pointer-restoration machinery. No other mapped format was introduced: `.linked/owner` and generation `.meta` files are ordinary private ownership/cache manifests, not mmap files.

The directory-shaped relation is **under `view/records/`**, not loose record entries mixed with user files in the view root. It preserves source record/group paths, with one symlink per projected existing scalar field, named by its projection alias. Excluded fields are not linked; absent optional fields have no file. SQL retains typed NULL semantics; raw bytes alone do not distinguish NULL from an empty field. Direct scalar physical fields and aliases (and `*` when every expanded item is eligible) are supported. Computed/capture/collection projections, source views, multiple sources/branches and LINKED reads inside explicit transactions return 7 rather than silently materializing copied values or publishing pending data. Ordinary saved views still support their broader existing typed grammar.

### Freshness / publication

Initial creation populates links. Without a running watcher, **SELECT through the view and CHECK VIEW refresh lazily**, using the same source query/filter/order/limit and pinned directory identity. The source shared lock is retained through link construction; an exclusive view lock serializes refresh. All new field links/directories/manifests are synced before an atomic rename publishes `records -> .linked/<generation>`. SQL results and refreshed membership are computed from the same locked source snapshot. An unchanged source generation/definition/membership reuses the previous directory snapshot.

Source INSERT/UPDATE/DELETE/record-rename membership changes appear in the physical tree on the next SQL access/check. Existing field symlinks resolve replacement source bytes immediately while their paths remain valid. **Raw filesystem browsing is not continuously refreshed or a transaction snapshot**: membership can be stale/dangling until refresh, and source bytes can change independently. An explicit filesystem watcher is now available as described below; no commit-event-only refresh or invisible background persistence is claimed. If initial population fails after definition publication, CREATE reports committed-pending status 6; a later SELECT retries refresh.

Only the owned `records` pointer and private `.linked` namespace are managed. Unrelated root entries are preserved. Foreign `records` files/links or invalid ownership manifests fail without replacement. Duplicate/unsafe projection names fail. Historical generations (including any user-added contents) are retained, not recursively deleted; metadata disk use grows with refreshed source generations, and automatic garbage collection is not included. Plain DROP remains definition-only and preserves these links, historical directories and all source data.

Views reject SQL mutations. **Symlinks are not OS access control**: a user with source write permission can modify source bytes by writing through a raw field link. Keep private managed namespaces unedited; noncooperating raw source edits/renames are not SQL transactions.

### Explicit filesystem-driven refresh (single-source LINKED views)

```sh
sql watch "VIEW '/tmp/adult-view' DEBOUNCE 100"
# Keep that foreground process running; browse from another terminal/program:
# cd /tmp/adult-view; ls records; cat records/a/label
# Ctrl-C / SIGTERM stops it cleanly. Optional bounded run (milliseconds):
sql watch "VIEW '/tmp/adult-view' DURATION 30000 DEBOUNCE 100"
```

This uses the actual trigger unit's recursive `Trig_Open/Add/Poll/Close` API, not just SQL commit events. A startup scan catches offline changes, new record directories acquire watches, close-write/rename/delete/directory hints are coalesced (100 ms default, configurable 1–5000 ms), and a full reconciliation every approximately one second covers missed hints. The trigger library rebuilds watches after queue overflow; actual kernel overflow saturation was not tested. One watcher per view is enforced by a private zero-byte `.sql-view-watch` lease. There is **no automatic daemon/service/startup installation**; restart this command after it exits. Source/view directory identities are pinned, descriptor-anchored and rechecked; replacements fail closed, not retargeted. The view must be outside the source tree to avoid refresh feedback. The canonical source watch path is conservatively limited to 255 bytes; long descendant event-path limitations are covered by periodic full reconciliation, not a guarantee of every event callback.

While running, ordinary filesystem source writes (including overwriting or appending through an intact view field symlink), source field removal, atomic source-file replacement, and source record additions/deletions update raw directory membership without SELECT/CHECK or SQL libraries in the writer/reader. Appending changes the whole field value: TEXT gets appended bytes; INT64 `20` appended with `0` becomes `200`, while `200x` is invalid. SQL reads validate values when used; CHECK remains strict. Read queries now treat an absent field as SQL NULL, including required fields; CHECK still reports the required-count violation. The watcher never recreates missing source files or deletes user bytes.

External writes are **asynchronous and not SQL transactions**. Close-write/debounce reduces partial-copy sampling but cannot prevent a long open writer or concurrent raw edits from being sampled by startup/periodic scans. Prefer complete-file atomic replacement at the actual source path when coherent file publication matters. Invalid/transient input logs a deferred status and retries; last-good membership may remain while existing raw symlinks already expose changed/invalid bytes. Final JSON reports refresh/failure/wakeup counters and last status. This is not an AFTER-trigger log or durable transaction for raw writes.

Unlinking a generated view field symlink does **not** unlink its source. Replacing the view symlink itself (for example an editor's rename or `cp --remove-destination`) is not the same as writing through it; those local projection edits are not reverse-propagated and may remain until a later snapshot rebuild. Raw symlinks remain ordinary OS links, not an access-control boundary. Existing source/payload and unrelated view entries are preserved. See MANUAL.md and this document for remaining limits.

### Still outside this bounded slice

Named independent multi-query branches are now available via `LINKED BRANCHES`; see [MULTI_VIEWS.md](MULTI_VIEWS.md). Persistent cross-table dependency registries, dependency-aware DROP/ALTER, transaction-atomic view DDL and transactional linked snapshots remain unfinished. No JOIN/UNION support or full-unit completion is implied. See [MANUAL.md](MANUAL.md) §17 and this document for the current limits.

## Named branches

For several independent source queries under one root, use `VIEW root LINKED BRANCHES (name AS SELECT ... ; other AS SELECT ...)`. Each named directory is a queryable LINKED view with its own records tree. Root queries explicitly select `BRANCH name`; one `WATCH VIEW root` refreshes all distinct sources. See [MULTI_VIEWS.md](MULTI_VIEWS.md) for exact syntax, decoder/replay limits and non-atomic freshness semantics.
