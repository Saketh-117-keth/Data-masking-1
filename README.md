# Smart Data Masking System for PII Protection

Scans a database for PII, then masks sensitive columns **at query time** based on the caller's role.
Stored data is never modified (queries run on read-only connections).

## Run

```bash
pip install streamlit pandas
python seed.py               # creates data/bank.db (synthetic data)
python cli.py scan           # PII scan report
python cli.py compare "SELECT full_name, ssn, card_number, balance FROM customers c JOIN accounts a ON a.customer_id=c.customer_id LIMIT 3"
streamlit run streamlit_app.py   # dashboard at http://localhost:8501
python -m unittest -v        # tests
```

## How it maps to the problem statement

| Expected outcome | Where |
|---|---|
| Automated PII scanner (column names + data samples, regex/rules, tags like PII_HIGH / FINANCIAL_CONFIDENTIAL) | `masking/scanner.py` |
| Dynamic masking engine, DB-agnostic (2+ backends) | `masking/engine.py`, `masking/backends.py` |
| Role-based policy (Admin full, Support partial, Analyst redact/hash) | `masking/maskers.py` (`POLICIES`) |
| Demo interface (role toggle, real-time results, tables intact) | `streamlit_app.py` (dashboard), `cli.py` |

## Role policy

| Tag | admin | support | analyst |
|---|---|---|---|
| PII_HIGH (SSN, card) | full | partial `4111-XXXX-XXXX-1111`, `XXX-XX-6789` | keyed hash |
| PII_MEDIUM (name, email, phone, dob, address) | full | partial | redacted |
| FINANCIAL_CONFIDENTIAL (balance, account no.) | full | balance range, last 4 | redacted |

Unknown roles are fully redacted (fail closed). Edit `POLICIES` to change behaviour.

## Design notes

- **Scanner:** name rules plus content rules (email, SSN, Luhn-valid card, Aadhaar, phone). Content wins over a
  misleading name (`customers.contact` holds emails and is still caught).
- **Lineage:** aliases (`ssn AS x`), expressions (`balance*2`) and `SELECT *` are handled. An expression using
  a sensitive column gets the strictest tag involved, so `SUM(balance)` is masked for roles that cannot see balances.
  If a column can't be traced, a content check runs on the returned values.
- **Safety:** only a single SELECT/WITH is accepted; SQLite is opened with `mode=ro` plus an authorizer that
  blocks ATTACH/PRAGMA/writes; every query is written to `data/audit.log`.
- **Hashing** is HMAC-SHA256 with a secret (`MASKING_SECRET` env var), so equal values stay joinable but cannot be reversed.

## Backends

`Backend` is a 4-method interface (`list_tables`, `list_columns`, `execute_readonly`, `quote`).
- `SQLiteBackend`: implemented and tested.
- `PostgresBackend` (psycopg2) and `MySQLBackend` (pymysql): implemented against `information_schema` with
  read-only sessions, but **not run in the build environment** (no drivers or servers available there). Test them
  against your own instance before demoing, e.g. `MaskingEngine(PostgresBackend("dbname=bank user=reader"))`.

## Known limits (mention these to evaluators)

- Lineage is regex-based, not a full SQL parser. Very complex queries (CTEs, UNION) fall back to name and content
  detection. For production use a real parser (e.g. `sqlglot`) or database-native masking policies/views.
- Numeric values (balances) are detected by column name only.
