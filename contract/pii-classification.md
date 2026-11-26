## PII classification

M5.1. Owner decisions M51-1 to M51-8. Every column an agent can read gets one class, for the whole database and every agent (M51-3). The engine's classifier suggests on a setup page, the person confirms, `basalt_meta` stores it ([PII objects](basalt-meta.md#pii-objects)). In M5.1 nothing is tokenized on the wire and nothing is refused: an unclassified column is only warned about (M51-5); refusals start in M5.2.

- **No value is ever printed, logged, written to the ledger or stored in plain form.** The pages and the engine show counts, column names and reasons; the dictionary holds keyed hashes; `basalt_meta` holds classes, never values.
- Agents can read the classification and never change it. Only the admin writes it, through a setup page's labels step, with the admin connection string the person typed there: the local setup page's install and its [`LABELS` fix](setup-page.md#the-update-check), and the connect page's setup ([Column labels on the connect page](connect.md#column-labels-on-the-connect-page)): the columns whose label the person changed, each checked against the class it had when the page read it, and on request `PUBLIC` for the columns that have no class; never a class erased. It writes as `<prefix>_guard`, with `confirmed_at` and `confirmed_by`, then `pii_catalog` ([Writing](connect.md#column-labels-on-the-connect-page)).

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

- **Readable columns** are the columns at least one member of `<prefix>_agents` may `SELECT` (`has_column_privilege(member, table, column, 'SELECT')`) and that same member has `USAGE` on the column's schema (`has_schema_privilege(member, schema, 'USAGE')`; without it the role cannot reach the column): ordinary columns (`attnum > 0`, not dropped) of tables, partitioned tables, views, materialized views and foreign tables, outside `pg_catalog`, `information_schema`, `pg_toast`, temporary schemas and `basalt_meta`. Row-level security does not change this: a column is readable when the role may select it, whatever rows it sees.
- **Data type** is `format_type(atttypid, NULL)`, without the type modifier (`character varying`, not `character varying(255)`), so a length change is not a type change.
- **Fingerprint** = `sha256` over the readable columns as lines `schema.table.column:type:table_oid:attnum`, built with `format('%I.%I.%I:%s:%s:%s', …)` so names are quoted as identifiers when they need it, sorted in byte order (`COLLATE "C"`) and joined by `"\n"`. Stored as `bytea`, shown as lowercase hex. It is the quick "did any readable column change" check; `pii_unclassified()` is the authority. One SQL definition, `pii_fingerprint()`, serves both the setup pages' labels step and the engine.
- **Renames and type changes** (M51-4). Classes are keyed by `(schema, table, column)` names, so a renamed column (or table) has no class and is `UNCLASSIFIED`; its old row stays until the next labels step that writes removes it ([`LABELS`](setup-page.md#the-update-check)), and no view shows it meanwhile. A type change keeps the class and marks the column for review (`TYPE_CHANGED`) until the next labels step records the new type ([`LABELS`](setup-page.md#the-update-check)).

### Suggestions

The engine's classifier, run by the check of a setup page's labels step (the local install's full check and its `LABELS` fix, [The Update check](setup-page.md#the-update-check)), with the admin connection, never by the agent.

- **What it does.** For each listed column it computes a suggested class, entity type, phone region and reason: name rules, and a sample of up to 1000 non-null values read with the admin connection. Values stay in the engine's memory and are dropped once the column is scored. Each value is cut to its first 256 characters before it is scored, and the sampling stops at 30 seconds of the call's 60; a column whose sample fails or runs out of time gets no suggestion.
- **Phone region.** Inferred per `PHONE` column from its sample (the region where most values are valid numbers, weighted by the `+cc` prefixes seen in the database), stored with the column so the engine normalizes that column's values the same way. When the sample holds no value to infer from, the region is null and the engine normalizes only numbers written with `+cc`.
- **Reasons** carry names and counts only, several joined by `; `: `NAME:email`, `SAMPLE:EMAIL 912/1000`, `SHAPE:99% distinct, fixed length 12`, `KEY:internal id`. No value appears in an answer, a log or a file.
- **Applied only when the person accepts.** A suggestion reaches the database only through the labels the page sends (`columnClasses`, `restPublic`). It never lowers a class a person confirmed.

**Removed: `basalt classify`**, with `--review`, `--set`, `--phone-region`, `--yes`, `--dry-run`, `--json` (its review schema `classify-review` goes with it) and `--check`. Labels are set on the setup page; a hint that named the command says to run `basalt init`.

### Engine and the Update check

- **Engine.** At start and on the hourly upkeep tick the engine calls `pii_unclassified()` as the agent and, when it returns rows, logs `pii: N columns unclassified: schema.table.column, …` (names are not PII). It loads `agent_pii_columns` at start and keeps, with the map, the `pii_fingerprint()` and `agent_pii_catalog` (`fingerprint`, `classified_at`) it read in the same transaction. On each hourly upkeep tick, the same tick that calls `pii_unclassified()`, it reads the three again and reloads the map when any of them differs from the values kept at the last load: `pii_fingerprint()` changes when readable columns are added, dropped, renamed or retyped, or a table is dropped and created again (its lines carry the table oid and attribute number), and the catalog changes when a setup page's labels step wrote. Between ticks, a result column whose table oid is not in the map (a table created again since the last load, say) makes the engine reload the map before it handles the values, at most once per oid per hourly tick, so a table with no classes does not reload on every query. A `(table oid, attnum)` still missing from the map after that is treated as `UNCLASSIFIED`: warned in M5.1, refused from M5.2. A move of `agent_pii_catalog.classified_at` (a labels step wrote) reloads the map at the hourly tick, as above; the engine may also reload at once when it sees one, which is optional (M51-7). It never compares `pii_fingerprint()` with `agent_pii_catalog.fingerprint`: the two differ from the moment a column changes until the next labels step, which is what `pii_unclassified()` reports.
- **Engine files** in `stateDir`: `pii.key` (`k_master`, 32 random bytes, mode `0600`, engine user; created on first start, refused at start when it is not a regular file with one link, is owned by another user or its mode is wider than `0600`; M51-1), the directory `pii/` (mode `0755`, engine user), `pii/dictionary.bin` (mode `0600`, engine user) and `pii/status.json` (mode `0644`, counts and times only, for the engine to report): `{ "dictionaryValues", "deltaValues", "fingerprintBits", "lastScanAt", "lastScanColumns", "lastScanRows", "updatedAt" }`, `fingerprintBits` `32` or `16`, times RFC 3339 UTC.
- **Engine config.** `engine.json` gains `pii: { "maxMemoryMB": 512, "scanRowsPerSecond": 20000 }` (the defaults). The engine sets `GOMEMLIMIT` to twice `maxMemoryMB` unless the environment sets it. `basalt service install` writes the service's memory limits from `maxMemoryMB` at install time: on Linux `MemoryHigh` (3×) and `MemoryMax` (4×) in the systemd unit. They do not follow a later edit of `engine.json`: after raising `maxMemoryMB`, run `basalt service install` again (with the same flags) so the unit is rewritten, or the engine may be throttled or stopped below its new budget. On macOS the plist carries `SoftResourceLimits`/`HardResourceLimits` `ResidentSetSize` with the same values, but current macOS does not enforce `ResidentSetSize`: there the limit is only `GOMEMLIMIT`, and the OS may evict the mapped dictionary's pages under pressure.
- **Unlabeled columns.** The [Update check](setup-page.md#the-update-check) shows the columns `pii_unclassified()` returns for the agent's role with `why` `NEW` or `UNCLASSIFIED`, and its `LABELS` fix labels them. `basalt log` and its PII line are removed.
- **`basalt init`** prints only its link. The install's labels step and the Update check are where the person sees unlabeled columns.
