# Operational migrations — API-Claimer backend

Manual, one-time database operations. The application performs **no** destructive DDL and
never builds these indexes — run them once as an operator (Supabase SQL editor or a one-shot
job). Everything here is idempotent.

---

## 1. `api_claims` stats index (speeds up the Claims tab)

**Why.** `GET /api/cust/stats` runs a recent-claims query
`… WHERE telegram_id = ? AND created_at >= ? ORDER BY created_at DESC, id DESC LIMIT 51`.
`api_claims` had no index on `created_at`, so Postgres sorted all of a buyer's in-window rows
on every request — cheap when small, but growing with data. Measured on a 500k-row table with a
busy 50-slot buyer (25k rows in the 7-day window) the recent query was **p95 ≈ 19.8ms / p99 ≈
30.7ms** (full Sort). With the index below it is **p95 ≈ 0.3–0.6ms**, flat as the table grows.

**Chosen index (evidence-based).** `(telegram_id, created_at DESC, id DESC)` — it matches the
`ORDER BY` exactly, so the plan is a plain index scan + `LIMIT` with **no Sort node**, at any size.
A two-column `(telegram_id, created_at)` was compared with `EXPLAIN (ANALYZE, BUFFERS)` and
rejected: it keeps a Sort (index is ASC) and, because claims recorded in one transaction share
`created_at` (`func.now()` = transaction time), it degrades to an **Incremental Sort** — on a tie
test (20k rows over 50 timestamps) it touched **867 buffers / 0.78ms** vs this index's **107
buffers / 0.08ms** (~10× worse). This index also serves the per-window aggregate's range filter.
Cost: ~39 MB at 1M rows and slightly higher per-insert maintenance — accepted for the read win.

### Run once (OUTSIDE any transaction — `CREATE INDEX CONCURRENTLY` cannot run in one):

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_api_claims_tid_created_at_id
  ON api_claims (telegram_id, created_at DESC, id DESC);
```

**Do this in a QUIET window** — not during a rolling deploy or mass reboot. On every boot the app
runs `ensure_api_claim_columns()` (a short `ALTER TABLE … ADD COLUMN` + non-concurrent
`CREATE INDEX IF NOT EXISTS`, all `IF NOT EXISTS` no-ops once present) which takes brief locks on
`api_claims`. That cannot deadlock with this build (single table → no lock cycle) but they can
**block** each other, and `CREATE INDEX CONCURRENTLY` waits for all in-flight transactions. Before
running, confirm nothing is holding a long/idle transaction on the table:

```sql
SELECT pid, state, xact_start, query
FROM pg_stat_activity
WHERE state IN ('idle in transaction', 'active')
  AND query ILIKE '%api_claims%'
ORDER BY xact_start;
```

The app logs one `WARNING` at startup (`stats index … is MISSING`) until this is applied, then is
silent. The app **never** builds this index and **never** waits on it — readiness is independent.

### Invalid-index recovery (operator-only; the app never does this)

An interrupted `CREATE INDEX CONCURRENTLY` leaves an **invalid** index. Detect → confirm → drop
concurrently → recreate concurrently. Never let application code perform this drop.

```sql
-- 1) detect a failed/invalid build:
SELECT c.relname
FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
WHERE c.relname = 'ix_api_claims_tid_created_at_id' AND i.indisvalid = false;

-- 2) if the above returns a row, drop it (outside a transaction) and re-create:
DROP INDEX CONCURRENTLY IF EXISTS ix_api_claims_tid_created_at_id;
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_api_claims_tid_created_at_id
  ON api_claims (telegram_id, created_at DESC, id DESC);
```

### Optional follow-up (not required)

Once this index exists, the existing single-column `ix_api_claims_telegram_id` is a redundant prefix
of it. Dropping it would save space and write overhead, but it is a separate change (other queries
may rely on it) — evaluate independently; not part of this migration.

---

### Verification performed before shipping (all against a real Postgres 18)

- **Merge equivalence** (the `/stats` code now runs 2 queries instead of 3): the real endpoint's
  full JSON is byte-for-byte identical to the former 3-query output across every
  `window × type` on rich data (multi-currency incl. a zero-amount currency, NULL currency/username,
  claimed+unclaimed, drop/bonus/reload, boundary timestamps, >50-row truncation, adversarial float
  magnitudes). A negative control confirmed the comparison catches the zero-amount-key regression.
- **Index choice**: `EXPLAIN (ANALYZE, BUFFERS)` across 10k/100k/1M rows × 1/10/50 slots × 24h/7d/30d;
  p50/p95/p99 flat after the index, degrading before it.
- **Migration safety**: `CONCURRENTLY` rejected inside a transaction, builds in autocommit;
  invalid-index detect + drop-concurrently + recreate yields a valid index; the app issues no
  composite DDL and no application source performs `DROP INDEX`.
