"""Dynamic masking engine.

Flow for every query:
  1. validate: single read-only SELECT/WITH statement
  2. run it against the backend on a read-only connection (raw data is never touched)
  3. work out, for each output column, which sensitive source column it came from
       - direct column / alias        -> that column's tag
       - expression using a tagged col -> strictest tag involved (safe default)
       - SELECT * / unparseable        -> match by result column name
       - still unknown                 -> content check on the returned values
  4. apply the role's action (none / partial / hash / redact) to those columns
  5. write an audit record
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field

from . import scanner
from .maskers import action_for, apply_mask
from .scanner import TAG_BY_TYPE, TAG_RANK, ColumnTag


class QueryRejected(ValueError):
    pass


@dataclass
class QueryResult:
    role: str
    columns: list[str]
    rows: list[list]
    column_report: list[dict]
    truncated: bool = False
    row_count: int = 0


# ---- light SQL parsing (no external deps) --------------------------------
def _flatten(sql: str) -> str:
    """Same length as sql; quoted text and anything inside parentheses becomes spaces."""
    out, depth, quote = [], 0, None
    for ch in sql:
        if quote:
            out.append(" ")
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
            out.append(" ")
        elif ch == "(":
            depth += 1
            out.append("(")
        elif ch == ")":
            depth = max(depth - 1, 0)
            out.append(")")
        else:
            out.append(ch if depth == 0 else " ")
    return "".join(out)


def select_items(sql: str) -> list[str] | None:
    """Top-level select-list expressions, or None when the query is too complex to parse."""
    flat = _flatten(sql)
    head = re.match(r"\s*select\b(\s+distinct\b)?", flat, re.I)
    if not head or re.search(r"\b(union|intersect|except)\b", flat, re.I):
        return None
    m_from = re.search(r"\bfrom\b", flat, re.I)
    end = m_from.start() if m_from else len(flat)
    items, last = [], head.end()
    for m in re.finditer(",", flat[head.end():end]):
        pos = head.end() + m.start()
        items.append(sql[last:pos])
        last = pos + 1
    items.append(sql[last:end])
    return [i.strip() for i in items]


BARE_COLUMN = re.compile(r'(?:\w+\.)?"?(\w+)"?(?:\s+(?:as\s+)?"?\w+"?)?', re.I)


class MaskingEngine:
    def __init__(self, backend, catalog_path="data/pii_catalog.json", audit_path="data/audit.log",
                 secret: str | None = None, max_rows: int = 1000):
        self.backend = backend
        self.catalog_path = catalog_path
        self.audit_path = audit_path
        self.secret = secret or os.environ.get("MASKING_SECRET", "demo-secret-change-me")
        self.max_rows = max_rows
        self.tags: list[ColumnTag] = []
        self._lookup: dict[str, ColumnTag] = {}
        if os.path.exists(catalog_path):
            self._set_tags(scanner.load_catalog(catalog_path))

    # -- catalog -----------------------------------------------------------
    def _set_tags(self, tags: list[ColumnTag]) -> None:
        self.tags = tags
        lookup: dict[str, ColumnTag] = {}
        for t in tags:  # same column name in several tables -> keep the strictest
            cur = lookup.get(t.column.lower())
            if cur is None or TAG_RANK[t.tag] > TAG_RANK[cur.tag]:
                lookup[t.column.lower()] = t
        self._lookup = lookup

    def scan(self, sample_size: int = 200) -> list[ColumnTag]:
        tags = scanner.scan(self.backend, sample_size)
        scanner.save_catalog(self.catalog_path, tags)
        self._set_tags(tags)
        return tags

    # -- querying ----------------------------------------------------------
    def _validate(self, sql: str) -> str:
        sql = (sql or "").strip().rstrip(";").strip()
        if not sql:
            raise QueryRejected("Empty query.")
        if ";" in _flatten(sql):
            raise QueryRejected("Only a single statement is allowed.")
        if not re.match(r"(select|with)\b", sql, re.I):
            raise QueryRejected("Only read-only SELECT queries are allowed.")
        return sql

    def _source_tag(self, name: str, expr: str | None):
        """Return (ColumnTag | None, how) for one output column."""
        if expr is not None:
            if re.match(r"count\s*\(", expr, re.I):
                return None, None
            cleaned = re.sub(r"'[^']*'", "", expr)
            hits = [self._lookup[i.lower()] for i in re.findall(r"[A-Za-z_]\w*", cleaned) if i.lower() in self._lookup]
            if not hits:
                return None, None
            bare = BARE_COLUMN.fullmatch(expr.strip())
            if bare and len(hits) == 1:
                return hits[0], "column"
            return max(hits, key=lambda t: TAG_RANK[t.tag]), "expression"
        hit = self._lookup.get(name.lower())
        return (hit, "name") if hit else (None, None)

    @staticmethod
    def _content_type(values) -> str | None:
        vals = [v for v in values if v is not None]
        if not vals:
            return None
        kinds = [scanner.detect_value_type(v) for v in vals]
        best = max(set(kinds), key=kinds.count)
        if best and kinds.count(best) / len(vals) >= 0.6:
            return best
        return None

    def query(self, role: str, sql: str, params=()) -> QueryResult:
        sql = self._validate(sql)
        cols, rows, truncated = self.backend.execute_readonly(sql, params, self.max_rows)

        items = select_items(sql)
        use_items = bool(items) and len(items) == len(cols) and not any(i == "*" or i.endswith(".*") for i in items)

        report, plans = [], []
        for i, name in enumerate(cols):
            tag, how = self._source_tag(name, items[i] if use_items else None)
            if tag is not None:
                dtype, tag_name = tag.data_type, tag.tag
            else:
                ctype = self._content_type(r[i] for r in rows)
                if ctype:
                    dtype, tag_name, how = ctype, TAG_BY_TYPE[ctype], "content"
                else:
                    plans.append(None)
                    continue
            action = action_for(role, tag_name)
            plans.append((action, dtype))
            report.append({"column": name, "tag": tag_name, "data_type": dtype,
                           "action": action, "detected_by": how})

        masked = [
            [apply_mask(v, *plans[i], self.secret) if plans[i] else v for i, v in enumerate(row)]
            for row in rows
        ]
        result = QueryResult(role, cols, masked, report, truncated, len(masked))
        self._audit(role, sql, report, len(masked))
        return result

    # -- audit -------------------------------------------------------------
    def _audit(self, role, sql, report, nrows) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "role": role,
            "sql": sql,
            "rows": nrows,
            "protected": [f'{r["column"]}:{r["action"]}' for r in report if r["action"] != "none"],
        }
        try:
            os.makedirs(os.path.dirname(self.audit_path) or ".", exist_ok=True)
            with open(self.audit_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # auditing must never break a query path in the demo

    def recent_audit(self, n: int = 20) -> list[dict]:
        if not os.path.exists(self.audit_path):
            return []
        with open(self.audit_path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh.readlines()[-n:]][::-1]
