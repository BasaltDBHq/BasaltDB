## PII classification

M5.1. Owner decisions M51-1 to M51-8. Every column an agent can read gets one class, for the whole database and every agent (M51-3). `basalt classify` suggests, the person confirms, `basalt_meta` stores it ([version 15](basalt-meta.md#version-15-pii-classification)). In M5.1 nothing is tokenized on the wire and nothing is refused: an unclassified column is only warned about (M51-5); refusals start in M5.2.

- **No value is ever printed, logged, written to the ledger or stored in plain form.** The CLI and the engine print counts, column names and reasons; the dictionary holds keyed hashes; `basalt_meta` holds classes, never values.
- Agents can read the classification and never change it. Only the admin writes it, through `basalt classify`.

### Classes

| Class | Meaning |
|---|---|
| `PUBLIC` | Leaves the machine as is |
| `IDENTIFIER` | One person's value, with an entity type: in the dictionary (M5.1) and tokenized on the wire (M5.3) |
| `FREE_TEXT` | Text that may mention people: patterns and the dictionary are applied to it (M5.3). Detection is deterministic: see [What free-text detection masks](#what-free-text-detection-masks) |
| `SECRET` | The engine refuses to read it at all (M5.2) |
| `UNCLASSIFIED` | No person has classified it: warned in M5.1, refused from M5.2. A new or renamed column starts here (M51-4) |

CLI spelling: `public`, `identifier`, `free-text`, `secret`, `unclassified`.

#### What free-text detection masks

Owner decision DD-1. Detection in core is deterministic: it masks only what it matches exactly or validates, and never guesses from context.

- **Masked:**
  - a value stored in an `IDENTIFIER` column, when free text holds it exactly, compared after normalizing (case and width), within known limits. The main ones: a value is found only when it has at most 4 words with at most 3 characters between them; only a two-word `PERSON_NAME` is also found in reversed order; a single common word never matches alone;
  - an email address, by its shape;
  - a phone number: a `+` number that libphonenumber says is valid; a `00` number that holds a separator and has a length its country dials, by its shape; and the US form `(202) 555-0143`, by its shape. A `+` number that libphonenumber says is only possible, not valid, is not masked, whatever word stands next to it (owner decision Q-14);
  - a 13 to 19 digit card number from a known issuer range that passes Luhn;
  - an IBAN that passes its checksum.
- **Not masked in free text:** a stored one-word value that is also a common word (`Rose`, `Hope`, `Price`), whatever stands around it (a title, a greeting, a capital letter, a JSON field); it is masked in its own column and as part of a stored full name (`Rose Lepik`). A name the database does not hold is not masked. Heuristics that guess names are left to an opt-in plugin.

### Entity types

Only for `IDENTIFIER`: every `IDENTIFIER` column has exactly one, and no other class has one.

| Entity type | Holds |
|---|---|
| `EMAIL` | Email addresses |
| `PHONE` | Phone numbers; the column also stores its phone region |
| `PERSON_NAME` | People's names |
| `ADDRESS` | Postal addresses and their parts (street, postcode) |
| `OTHER` | Any other identifier of a person: IBANs, dates of birth, IMEIs, account numbers |

CLI spelling: `email`, `phone`, `person-name`, `address`, `other`.

### Readable columns and the fingerprint

- **Readable columns** are the columns at least one member of `<prefix>_agents` may `SELECT` (`has_column_privilege(member, table, column, 'SELECT')`) and that same member has `USAGE` on the column's schema (`has_schema_privilege(member, schema, 'USAGE')`, from version 27; without it the role cannot reach the column): ordinary columns (`attnum > 0`, not dropped) of tables, partitioned tables, views, materialized views and foreign tables, outside `pg_catalog`, `information_schema`, `pg_toast`, temporary schemas and `basalt_meta`. Row-level security does not change this: a column is readable when the role may select it, whatever rows it sees.
- **Data type** is `format_type(atttypid, NULL)`, without the type modifier (`character varying`, not `character varying(255)`), so a length change is not a type change.
- **Fingerprint** = `sha256` over the readable columns as lines `schema.table.column:type:table_oid:attnum`, built with `format('%I.%I.%I:%s:%s:%s', …)` so names are quoted as identifiers when they need it (version 19; up to version 18, `schema.table.column:type` unquoted), sorted in byte order (`COLLATE "C"`) and joined by `"\n"`. Stored as `bytea`, shown as lowercase hex. It is the quick "did any readable column change" check; `pii_unclassified()` is the authority. One SQL definition, `pii_fingerprint()`, serves both `basalt classify` and the engine.
- **Renames and type changes** (M51-4). Classes are keyed by `(schema, table, column)` names, so a renamed column (or table) has no class and is `UNCLASSIFIED`; its old row stays until the next `basalt classify` removes it, and no view shows it meanwhile. A type change keeps the class and marks the column for review (`TYPE_CHANGED`) until `basalt classify` records the new type.

### `basalt classify`

```text
basalt classify [--review=changed|all] [--set schema.table.column=class[:entity-type]]...
                [--phone-region=auto|XX] [--yes] [--dry-run] [--json] [--check]
```

- **Credential.** The admin connection string comes from `BASALT_ADMIN_DATABASE_URL` or a hidden prompt, as for `basalt init`; it is used for this run only and never written anywhere. The CLI refuses to run when `basalt_meta` is missing or older than version 15: `basalt: guard schema vN has no PII classification; run basalt init again to upgrade it (same flags as before)`, exit `1`.
- **What it does.** Lists the readable columns, computes a suggestion and its reason for each (name rules, and a sample of up to 1000 non-null values read with the admin connection; values stay in the CLI's memory and are dropped after scoring), shows the review, and writes what is accepted.
- **`--review`** (default `changed`): `changed` shows only columns that are `NEW` (no row), `UNCLASSIFIED` (a row of that class), `TYPE_CHANGED`, flagged `needsReview`, or whose suggestion differs from the confirmed class; `all` shows every readable column. Columns not shown keep their class.
- **The review**, grouped by table: per column its name, data type, current class, suggestion with entity type, reason, and for a `PHONE` suggestion the region and its share (`parsed as ID numbers, 91%`). At a terminal, per table, the person accepts the table, edits a column (input `column=class[:entity-type]`, the `--set` spelling) or skips the table; a skipped table's columns stay `UNCLASSIFIED`. A column flagged `needsReview` is asked about on its own even when its table is accepted. The terminal layout is layout C, "summary first" (owner decision OR-4): a count line, then per table the columns grouped by class with `SECRET` first, each needs-review column asked on its own (`Protect <col> as IDENTIFIER? [Y/n]`; no asks for the class) before `Accept the rest for <table>? [Y/e/s]`; below 100 terminal columns the reason moves to a second indented line. This contract fixes what the review contains and the `--json` shape.
- **`--set schema.table.column=class[:entity-type]`** (repeatable): sets those columns' classes without the review; nothing else is written. The entity type is required with `identifier` and refused with any other class. A column that is not readable, or a value outside the spellings above, is a usage error (exit `2`).
- **`--phone-region`** (default `auto`): `auto` infers the region per `PHONE` column from its sample (the region where most values are valid numbers, weighted by the `+cc` prefixes seen in the database); `XX`, an ISO 3166-1 alpha-2 code (input case-insensitive, stored upper case), is used for every `PHONE` column of the run instead. The region is stored per column so the engine normalizes that column's values the same way. When the sample holds no value to infer from, the region is null and the engine normalizes only numbers written with `+cc`.
- **`--yes`**: prints the review, then accepts every suggestion shown without asking; a column flagged `needsReview` gets its protected suggestion and stays flagged. It never lowers a class a person confirmed: when the confirmed class protects more than the suggestion, the confirmed class stays. Without a terminal, `basalt classify` writes only with `--yes` or `--set`; otherwise it prints the review and exits `1` with `basalt: no terminal to confirm the classes; pass --yes to accept the suggestions or --set to set columns`.
- **`--dry-run`**: computes and prints the review, asks nothing and writes nothing.
- **`--json`**: prints the review as JSON on stdout instead of text ([`classify-review.schema.json`](../api/mcp/pii/classify-review.schema.json)) and asks nothing: it writes only with `--yes` or `--set`, and `written` says whether it did.
- **Writing.** One transaction under `SET LOCAL ROLE <prefix>_guard` ([Writer](basalt-meta.md#version-15-pii-classification)), in plain DML: upserts the accepted columns of `pii_columns` (class, entity type, suggestion, reason, `needs_review`, `phone_region`, `data_type`, `confirmed_at`, `confirmed_by`), stores the suggestion and reason of every column shown but not accepted that has no class yet (class `UNCLASSIFIED`; a column a person confirmed earlier keeps its row), deletes the rows of columns that no longer exist (a confirmed class survives a revoked grant, owner decision OR-1), and sets `pii_catalog` to `pii_fingerprint()` and the time. It prints counts: `basalt: classified N columns (P PUBLIC, I IDENTIFIER, F FREE_TEXT, S SECRET); U columns stay UNCLASSIFIED`.
- **`--check`**: writes nothing and shows every column (as `--review=all`). For every `IDENTIFIER` column (the confirmed class, else the suggestion) it takes the sample and, in memory, makes each value's token, restores it and tokenizes the restored text again; it prints per column the values sampled and how many do not come back to the same token (`public.customers.full_name: 1000 sampled, 3 do not round-trip`), naming the common-word rule when that is the cause. No value is printed. Exit `0` when it ran, whatever the counts; with `--json` each checked column carries `check`.
- **Output.** No value appears anywhere. Reasons carry names and counts (`NAME:email`, `SAMPLE:EMAIL 912/1000`, `SHAPE:99% distinct, fixed length 12`, `KEY:internal id`), several joined by `; `. Exit codes `0` ok, `1` error, `2` usage.

### `--json` review

[`api/mcp/pii/classify-review.schema.json`](../api/mcp/pii/classify-review.schema.json): `{ "fingerprint", "previousFingerprint", "review", "dryRun", "written", "tables": [{ "table", "columns": [...] }] }`, `review` `CHANGED` or `ALL`. Each column: `column`, `dataType`, `status` (below), `class` (the stored class, `UNCLASSIFIED` when there is no row), `entityType`, `suggestedClass`, `suggestedEntityType`, `reason`, `needsReview`, `phoneRegion`, and with `--check` `check: { "sampled", "roundTripFailures", "commonWordRule" }`. `entityType`, `suggestedEntityType`, `phoneRegion` and `previousFingerprint` are absent when they do not apply. Enum values as in [Classes](#classes) and [Entity types](#entity-types). The schema enforces that `entityType` is present exactly when `class` is `IDENTIFIER`, `suggestedEntityType` exactly when `suggestedClass` is `IDENTIFIER`, and `phoneRegion` only when one of them is `PHONE`.

`status`, why a column is shown: the first row that applies.

| Status | When |
|---|---|
| `NEW` | No row in `pii_columns` |
| `UNCLASSIFIED` | A row of class `UNCLASSIFIED` |
| `TYPE_CHANGED` | The stored `data_type` differs from the column's type now |
| `NEEDS_REVIEW` | Flagged `needs_review` |
| `SUGGESTION_DIFFERS` | The suggestion differs from the confirmed class or entity type |
| `UNCHANGED` | None of the above; shown only with `--review=all` |

### Engine, `basalt log` and `basalt init`

- **Engine.** At start and on the hourly upkeep tick the engine calls `pii_unclassified()` as the agent and, when it returns rows, logs `pii: N columns unclassified: schema.table.column, …` (names are not PII). It loads `agent_pii_columns` at start and keeps, with the map, the `pii_fingerprint()` and `agent_pii_catalog` (`fingerprint`, `classified_at`) it read in the same transaction. On each hourly upkeep tick, the same tick that calls `pii_unclassified()`, it reads the three again and reloads the map when any of them differs from the values kept at the last load: `pii_fingerprint()` changes when readable columns are added, dropped, renamed or retyped, or a table is dropped and created again (from version 19 its lines carry the table oid and attribute number), and the catalog changes when `basalt classify` ran. Between ticks, a result column whose table oid is not in the map (a table created again since the last load, say) makes the engine reload the map before it handles the values, at most once per oid per hourly tick, so a table with no classes does not reload on every query. A `(table oid, attnum)` still missing from the map after that is treated as `UNCLASSIFIED`: warned in M5.1, refused from M5.2. A move of `agent_pii_catalog.classified_at` (a `basalt classify` ran) reloads the map at the hourly tick, as above; the engine may also reload at once when it sees one, which is optional (M51-7). It never compares `pii_fingerprint()` with `agent_pii_catalog.fingerprint`: the two differ from the moment a column changes until the next `basalt classify`, which is what `pii_unclassified()` reports.
- **Engine files** in `stateDir`: `pii.key` (`k_master`, 32 random bytes, mode `0600`, engine user; created on first start, refused at start when its mode is wider than `0600`; M51-1), the directory `pii/` (mode `0755`, engine user), `pii/dictionary.bin` (mode `0600`, engine user) and `pii/status.json` (mode `0644`, counts and times only, so the person's `basalt log` can read it): `{ "dictionaryValues", "deltaValues", "fingerprintBits", "lastScanAt", "lastScanColumns", "lastScanRows", "updatedAt" }`, `fingerprintBits` `32` or `16`, times RFC 3339 UTC.
- **Engine config.** `engine.json` gains `pii: { "maxMemoryMB": 512, "scanRowsPerSecond": 20000 }` (the defaults). The engine sets `GOMEMLIMIT` to twice `maxMemoryMB` unless the environment sets it. `basalt service install` writes the service's memory limits from `maxMemoryMB` at install time: on Linux `MemoryHigh` (3×) and `MemoryMax` (4×) in the systemd unit. They do not follow a later edit of `engine.json`: after raising `maxMemoryMB`, run `basalt service install` again (with the same flags) so the unit is rewritten, or the engine may be throttled or stopped below its new budget. On macOS the plist carries `SoftResourceLimits`/`HardResourceLimits` `ResidentSetSize` with the same values, but current macOS does not enforce `ResidentSetSize`: there the limit is only `GOMEMLIMIT`, and the OS may evict the mapped dictionary's pages under pressure.
- **`basalt log`** prints one line on stderr, before its warnings, when the guard is version 15 or later: `PII: N columns classified, M unclassified; dictionary of K values, last scan <time>`. N counts the rows of `agent_pii_columns` with a class other than `UNCLASSIFIED`; K counts the dictionary's generic forms, so a two-word `PERSON_NAME`, stored in both orders, counts twice; M the rows of `pii_unclassified()` with `why` `NEW` or `UNCLASSIFIED`. When `status.json` is missing, cannot be read (permissions, an unreadable `stateDir`) or does not parse, the part after `;` is `dictionary not built yet`. It then warns on stderr `basalt: warning: M columns the agent can read are not classified yet: <names>; run basalt classify` when M > 0, and `basalt: warning: R columns need a classification review (type changed or flagged): <names>; run basalt classify` when any column is `TYPE_CHANGED` or has `needs_review`; at most 10 names each, then `…`. `--json` output is unchanged.
- **`basalt init`**, after installing, prints `basalt: N columns the agent can read are not classified yet; run basalt classify` when N > 0, N counted as `pii_unclassified()` counts for that agent's role (`why` `NEW` or `UNCLASSIFIED`).
