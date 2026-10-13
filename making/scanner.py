"""Automated PII scanner.

Scans schema metadata (column names) and row samples (regex / checksum rules)
and tags sensitive columns as PII_HIGH, PII_MEDIUM or FINANCIAL_CONFIDENTIAL.
The scanner only reads; it never alters the database.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field

# data_type -> sensitivity tag
TAG_BY_TYPE = {
    "credit_card": "PII_HIGH",
    "ssn": "PII_HIGH",
    "aadhaar": "PII_HIGH",
    "email": "PII_MEDIUM",
    "phone": "PII_MEDIUM",
    "full_name": "PII_MEDIUM",
    "address": "PII_MEDIUM",
    "dob": "PII_MEDIUM",
    "account_number": "FINANCIAL_CONFIDENTIAL",
    "balance": "FINANCIAL_CONFIDENTIAL",
}

# Higher number = stricter. Used when one output column maps to several tags.
TAG_RANK = {"PII_MEDIUM": 1, "FINANCIAL_CONFIDENTIAL": 2, "PII_HIGH": 3}

# Column-name rules (checked against the snake_case lowercase column name).
NAME_RULES = [
    ("ssn", r"(^|_)(ssn|social_?security\w*|national_?id|tax_?id)($|_)"),
    ("aadhaar", r"(^|_)aadh?aa?r\w*($|_)") ,
    ("credit_card", r"(credit|debit)_?card|(^|_)card_?(no|num|number)($|_)|(^|_)cc_?(no|num|number)?($|_)") ,
    ("account_number", r"(acct|account)_?(no|num|number)|(^|_)iban($|_)") ,
    ("email", r"e_?mail"),
    ("phone", r"(^|_)(phone|mobile|msisdn|tel|telephone|contact_?(no|num|number))($|_)") ,
    ("dob", r"(^|_)(dob|birth_?date|date_?of_?birth|birthday)($|_)") ,
    ("balance", r"(^|_)(balance|salary|income|net_?worth)($|_)") ,
    ("full_name", r"(^|_)(full|first|last|sur|customer|cust|holder)_?name$|^name$") ,
    ("address", r"(^|_)(address|street|zip|zipcode|postal|pincode)($|_)") ,
]

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
SSN_RE = re.compile(r"\d{3}-\d{2}-\d{4}")
CARD_RE = re.compile(r"\d{4}([- ])?\d{4}\1\d{4}\1\d{1,7}")
AADHAAR_RE = re.compile(r"\d{4}([ -]?)\d{4}\1\d{4}")
PHONE_RE = re.compile(r"\+?\d[\d\s\-().]{8,17}\d")


def normalize(name: str) -> str:
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def match_name(column: str) -> str | None:
    n = normalize(column)
    for dtype, pattern in NAME_RULES:
        if re.search(pattern, n):
            return dtype
    return None


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_value_type(value) -> str | None:
    """Classify a single value by its content. Numbers are left to name rules."""
    if value is None or isinstance(value, (int, float, bytes)):
        return None
    s = str(value).strip()
    if not s:
        return None
    if EMAIL_RE.fullmatch(s):
        return "email"
    if SSN_RE.fullmatch(s):
        return "ssn"
    if CARD_RE.fullmatch(s) and luhn_ok(s):
        return "credit_card"
    if AADHAAR_RE.fullmatch(s):
        return "aadhaar"
    if PHONE_RE.fullmatch(s) and 10 <= len(re.sub(r"\D", "", s)) <= 13:
        return "phone"
    return None


@dataclass
class ColumnTag:
    table: str
    column: str
    sql_type: str
    data_type: str
    tag: str
    confidence: float
    reasons: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.table}.{self.column}"


def scan(backend, sample_size: int = 200) -> list[ColumnTag]:
    """Scan every table/column of the backend and return the tagged columns."""
    found: list[ColumnTag] = []
    for table in backend.list_tables():
        for column, sql_type in backend.list_columns(table):
            name_type = match_name(column)
            samples = backend.sample(table, column, sample_size)
            counts = Counter(t for t in map(detect_value_type, samples) if t)
            value_type, ratio = None, 0.0
            if counts and samples:
                value_type, hits = counts.most_common(1)[0]
                ratio = hits / len(samples)

            reasons: list[str] = []
            if value_type and ratio >= 0.6:
                dtype = value_type
                reasons.append(f"{ratio:.0%} of {len(samples)} sampled values look like {value_type}")
                if name_type == value_type:
                    reasons.append(f"column name '{column}' also matches {name_type}")
                    confidence = 0.95
                else:
                    if name_type:
                        reasons.append(f"content overrides name hint '{name_type}'")
                    confidence = round(min(0.9, 0.5 + ratio * 0.4), 2)
            elif name_type:
                dtype = name_type
                reasons.append(f"column name '{column}' matches {name_type} rule")
                confidence = 0.7
            else:
                continue

            found.append(ColumnTag(table, column, sql_type, dtype, TAG_BY_TYPE[dtype], confidence, reasons))
    return found


def save_catalog(path: str, tags: list[ColumnTag]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(t) for t in tags], fh, indent=2)


def load_catalog(path: str) -> list[ColumnTag]:
    with open(path, encoding="utf-8") as fh:
        return [ColumnTag(**row) for row in json.load(fh)]
