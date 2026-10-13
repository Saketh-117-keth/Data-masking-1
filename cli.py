"""CLI demo:  python cli.py scan | query --role support "SELECT ..." | compare "SELECT ..." """
import argparse
import os
import sys

from masking import MaskingEngine, QueryRejected, SQLiteBackend
from seed import seed

DB = os.environ.get("BANK_DB", "data/bank.db")
ROLES = ["admin", "support", "analyst"]


def table(cols, rows, limit=15):
    rows = rows[:limit]
    widths = [max(len(str(c)), *(len(str(r[i])) for r in rows)) if rows else len(str(c)) for i, c in enumerate(cols)]
    line = "-+-".join("-" * w for w in widths)
    print(" | ".join(str(c).ljust(w) for c, w in zip(cols, widths)))
    print(line)
    for r in rows:
        print(" | ".join(str(v).ljust(w) for v, w in zip(r, widths)))


def main():
    ap = argparse.ArgumentParser(description="Smart Data Masking System")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan", help="scan the database and tag PII columns")
    q = sub.add_parser("query", help="run a query as a role")
    q.add_argument("--role", default="support")
    q.add_argument("sql")
    c = sub.add_parser("compare", help="run a query as every role")
    c.add_argument("sql")
    args = ap.parse_args()

    if not os.path.exists(DB):
        seed(DB)
    engine = MaskingEngine(SQLiteBackend(DB))
    if args.cmd == "scan" or not engine.tags:
        tags = engine.scan()
        if args.cmd == "scan":
            print(f"{'column':28} {'type':15} {'tag':24} conf  why")
            for t in tags:
                print(f"{t.key:28} {t.data_type:15} {t.tag:24} {t.confidence:<5} {'; '.join(t.reasons)}")
            return
    try:
        for role in ([args.role] if args.cmd == "query" else ROLES):
            res = engine.query(role, args.sql)
            print(f"\n=== role: {role} ({res.row_count} rows) ===")
            table(res.columns, res.rows)
    except QueryRejected as exc:
        sys.exit(f"Rejected: {exc}")


if __name__ == "__main__":
    main()
