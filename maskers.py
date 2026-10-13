"""Masking primitives and the role -> action policy table."""
from __future__ import annotations

import hashlib
import hmac
import re

# ---- role policy ---------------------------------------------------------
# action is one of: none | partial | hash | redact
POLICIES = {
    "admin": {"*": "none"},
    "support": {
        "PII_HIGH": "partial",
        "PII_MEDIUM": "partial",
        "FINANCIAL_CONFIDENTIAL": "partial",
    },
    "analyst": {
        "PII_HIGH": "hash",
        "PII_MEDIUM": "redact",
        "FINANCIAL_CONFIDENTIAL": "redact",
    },
}


def action_for(role: str, tag: str) -> str:
    """Fail closed: unknown roles and unknown tags are fully redacted."""
    policy = POLICIES.get((role or "").lower())
    if policy is None:
        return "redact"
    return policy.get(tag, policy.get("*", "redact"))


# ---- primitives ----------------------------------------------------------
REDACTED = "[REDACTED]"
BUCKETS = [0, 1_000, 10_000, 50_000, 100_000, 500_000, 1_000_000]


def _mask_keep(s: str, keep_first: int = 0, keep_last: int = 4, ch: str = "X") -> str:
    idx = [i for i, c in enumerate(s) if c.isalnum()]
    if len(idx) <= keep_first + keep_last + 1:  # too short to reveal anything safely
        keep_first, keep_last = 0, 0
    keep = set(idx[:keep_first]) | set(idx[len(idx) - keep_last:] if keep_last else [])
    return "".join(ch if (c.isalnum() and i not in keep) else c for i, c in enumerate(s))


def _bucket(value) -> str:
    try:
        x = float(value)
    except (TypeError, ValueError):
        return REDACTED
    if x < 0:
        return "< 0"
    for lo, hi in zip(BUCKETS, BUCKETS[1:]):
        if x < hi:
            return f"{lo:,} - {hi:,}"
    return f"{BUCKETS[-1]:,}+"


def hash_value(value, secret: str) -> str:
    """Keyed, deterministic hash: equal inputs stay joinable, raw value is not recoverable."""
    digest = hmac.new(secret.encode(), str(value).encode(), hashlib.sha256).hexdigest()
    return "h_" + digest[:12]


def partial_mask(value, data_type: str | None) -> str:
    if data_type == "balance":
        return _bucket(value)
    s = str(value)
    if data_type == "credit_card":
        return _mask_keep(s, keep_first=4, keep_last=4)  # 4111-XXXX-XXXX-1111
    if data_type in ("ssn", "aadhaar", "account_number", "phone"):
        return _mask_keep(s, keep_last=4)  # XXX-XX-6789
    if data_type == "email":
        local, _, domain = s.partition("@")
        return f"{local[:1]}***@{domain}" if domain else "***"
    if data_type == "full_name":
        return " ".join(w[:1] + "***" for w in s.split())
    if data_type == "address":
        parts = [p.strip() for p in s.split(",")]
        return f"*****, {parts[-1]}" if len(parts) > 1 else s[:1] + "***"
    if data_type == "dob":
        m = re.match(r"(\d{4})[-/]\d{2}[-/]\d{2}", s)
        return f"{m.group(1)}-XX-XX" if m else "XXXX-XX-XX"
    return _mask_keep(s, keep_last=2)


def apply_mask(value, action: str, data_type: str | None, secret: str):
    if value is None or action == "none":
        return value
    if action == "redact":
        return REDACTED
    if action == "hash":
        return hash_value(value, secret)
    if action == "partial":
        return partial_mask(value, data_type)
    return REDACTED  # unknown action -> fail closed
