"""WHOIS lookup module using python-whois."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict


def _serialize_value(value: Any) -> Any:
    """Convert WHOIS values into report-friendly serializable values."""
    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, list):
        return [str(_serialize_value(item)) for item in value]

    if value is None:
        return ""

    return str(value)


def run(domain: str) -> Dict:
    """Run WHOIS query and return structured domain registration details."""
    result = {
        "status": "success",
        "module": "whois_lookup",
        "domain": domain,
        "whois": {},
        "error": None,
    }

    try:
        try:
            import whois
        except Exception as exc:
            raise RuntimeError(f"python-whois is not installed: {exc}")

        raw = whois.whois(domain)
        formatted = {}

        # Normalize all fields so downstream report generation is simple.
        for key, value in dict(raw).items():
            formatted[key] = _serialize_value(value)

        result["whois"] = formatted
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result
