"""Validate a local CSV scope inventory; never resolve or contact assets."""
from __future__ import annotations
import argparse
import csv
import datetime as dt
import ipaddress
import json
import re
from pathlib import Path
from typing import Iterable

REQUIRED_COLUMNS = ("asset", "owner", "environment", "authorization_reference", "authorized_until", "last_reviewed")
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def valid_asset(value: str) -> bool:
    value = value.strip()
    if not value or "*" in value or "/" in value or "://" in value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    hostname = value[:-1] if value.endswith(".") else value
    if len(hostname) > 253:
        return False
    labels = hostname.split(".")
    return all(HOST_LABEL.fullmatch(label) for label in labels)


def parse_date(value: str):
    try:
        return dt.date.fromisoformat((value or "").strip())
    except ValueError:
        return None


def review(rows: Iterable[dict[str, str]], as_of: dt.date | None = None, stale_after_days: int = 90) -> dict:
    today = as_of or dt.date.today()
    findings = []
    seen: dict[str, int] = {}
    row_count = 0
    for number, row in enumerate(rows, start=2):
        row_count += 1
        asset = (row.get("asset") or "").strip()
        normalized = asset.lower().rstrip(".")
        if not asset:
            findings.append({"row": number, "severity": "error", "code": "missing_asset", "field": "asset"})
        elif not valid_asset(asset):
            findings.append({"row": number, "severity": "error", "code": "invalid_asset_format", "field": "asset"})
        elif normalized in seen:
            findings.append({"row": number, "severity": "error", "code": "duplicate_asset", "field": "asset", "first_row": seen[normalized]})
        else:
            seen[normalized] = number

        for field in ("owner", "environment", "authorization_reference"):
            if not (row.get(field) or "").strip():
                findings.append({"row": number, "severity": "error", "code": "missing_required_value", "field": field})

        expiry = parse_date(row.get("authorized_until", ""))
        if expiry is None:
            findings.append({"row": number, "severity": "error", "code": "invalid_authorization_date", "field": "authorized_until"})
        elif expiry < today:
            findings.append({"row": number, "severity": "error", "code": "authorization_expired", "field": "authorized_until", "date": expiry.isoformat()})

        reviewed = parse_date(row.get("last_reviewed", ""))
        if reviewed is None:
            findings.append({"row": number, "severity": "error", "code": "invalid_review_date", "field": "last_reviewed"})
        elif reviewed > today:
            findings.append({"row": number, "severity": "warning", "code": "review_date_in_future", "field": "last_reviewed", "date": reviewed.isoformat()})
        elif (today - reviewed).days > stale_after_days:
            findings.append({"row": number, "severity": "warning", "code": "stale_review", "field": "last_reviewed", "age_days": (today - reviewed).days})

    errors = sum(f["severity"] == "error" for f in findings)
    warnings = sum(f["severity"] == "warning" for f in findings)
    return {
        "rows_reviewed": row_count,
        "unique_assets": len(seen),
        "errors": errors,
        "warnings": warnings,
        "status": "needs-review" if findings else "ready-for-human-review",
        "findings": findings,
        "scope": "Local inventory validation only; no DNS lookups or network requests were made.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a local authorized-scope CSV inventory.")
    parser.add_argument("inventory", type=Path, help="CSV with the documented scope columns")
    parser.add_argument("--stale-after-days", type=int, default=90)
    args = parser.parse_args()
    if args.stale_after_days < 1:
        parser.error("--stale-after-days must be positive")
    try:
        with args.inventory.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
            if missing:
                parser.error("missing CSV columns: " + ", ".join(missing))
            result = review(reader, stale_after_days=args.stale_after_days)
    except OSError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
