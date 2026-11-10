# Named multi-query LINKED views (bounded implementation)

> **Update 2026-11-09:** see MANUAL.md §17. Branch roots now appear in `SHOW VIEWS`, take part in RESTRICT dependency checks and generation pruning (`ALTER VIEW root PRUNE GENERATIONS`).


```sh
sql create "VIEW '/tmp/combined' LINKED BRANCHES (people AS SELECT title AS name FROM '/tmp/people' WHERE age >= 18 ; invoices AS SELECT amount AS score FROM '/tmp/invoices' WHERE amount >= 10)"
cd /tmp/combined
sql select 'BRANCH people name'      # explicit root branch, no FROM override
cd invoices
sql select '*'                       # exact branch CWD, independent schema
# Also: sql select "score FROM '/tmp/combined/invoices'"
sql watch "VIEW '/tmp/combined' DEBOUNCE 100"
```

The root contains `people/records/<source-record>/name` and `invoices/records/<source-record>/score`. Fields are symlinks to their original source paths, never copied payloads. Identical record basenames in different branches do not collide. Each branch has its own projection/types/filter/order/limit; root SELECT without BRANCH fails rather than guessing a common schema. No implicit ancestor lookup is used. FROM is omitted in root BRANCH queries; query an exact branch path when specifying FROM.

Grammar is `CREATE|DEFINE VIEW [root] LINKED BRANCHES (name AS SELECT clauses ; name AS SELECT clauses ...)`. Bounds: 1–8 branches; names start with a letter and contain letters/digits/underscore/hyphen, at most 63 bytes. Duplicate, hidden or traversal names fail before output directories are created. Each source must be one physical table; existing scalar-only LINKED restrictions apply. Runtime bindings are not captured by this format: branch definitions must use literals. The existing 65535-byte active-command bound and per-query 16383-byte saved-query bound still apply.

## Definition / decoding

Root `.view` is pointer-free native **version 3**, exact-size/owner/endian checked, containing every branch name, source identity/query and managed branch directory identity. Child branch directories have existing version-2 LINKED `.view` maps and are independently queryable. Older incompatible readers reject version/size rather than reinterpreting it. Existing single-source syntax and formats remain supported.

`sql_viewmem /tmp/combined` uses actual mio descriptors for the header and branch array and dumps quoted TraceLevel plus C.Definition replay. Root/branch/source identities and definitions are read-only in this slice: replay onto a compatible provisioned root validates identical canonical definition text (no evaluation) and restores TraceLevel. Changed definitions are refused, not silently retargeted. To construct another root, use `sql describe "VIEW '/tmp/combined' AS DDL"` and CREATE/DEFINE that DDL at the new path; fresh directory identities are assigned. Editing a managed child's Query independently breaks the root-manifest validation and is not a supported way to modify a multi-view. Root Trace binds its actual shared mapped word and restores the caller before unmap; Trace-only mem updates preserve inode/generation.

## Refresh and safety

One foreground `sql watch "VIEW '/tmp/combined'"` watches every **distinct** source through the actual recursive trigger unit. Multiple branches over one source share its watch. Startup rescans catch offline edits; close-write/rename/delete hints plus periodic full reconciliation update raw branch trees without SELECT/CHECK in browsing programs. Restart the command after it exits. Ctrl-C/SIGTERM or DURATION milliseconds stops it; no daemon/autostart was installed.

Each branch refresh is independently source-locked and atomically publishes its own records pointer. This is **not a multi-table atomic snapshot**; branches may reflect different instants. Source append/overwrite/replacement, record addition/deletion and missing-field NULL behavior are the same as single-source LINKED views. Invalid input can leave last-good membership while raw links already expose changed bytes. Raw edits are asynchronous, not SQL transactions or AFTER-event logging. SQL mutations are refused; OS symlinks are not an access-control boundary, and deleting a view link is not source deletion.

Unrelated root files and historical generation contents are preserved. Foreign/moved/replaced branches or sources fail closed; no automatic adoption or hidden retargeting. Initial construction is not transactional DDL: interrupted/failed construction may leave owned branch directories, which are preserved rather than deleted/reinterpreted. Plain DROP remains definition-only and preserves child views/links/source data; RESTRICT/dependency registries are not implemented. Explicit transaction reads/DDL, joins, unions, schema coercion, mutable branch definitions and automatic historical-generation cleanup remain outside this slice. See [MANUAL.md](MANUAL.md) §17 and this document for the current limits.
