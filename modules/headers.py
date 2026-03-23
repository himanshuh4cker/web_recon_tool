"""HTTP security headers analysis module."""

from __future__ import annotations

from typing import Dict


REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def _fetch_headers(url: str, timeout: int = 12) -> Dict[str, str]:
    """Fetch HTTP response headers from a URL."""
    import requests

    session = requests.Session()
    # Keep redirect depth small to avoid long waits on redirect chains.
    session.max_redirects = 5

    # Prefer HEAD for speed; fallback to GET when HEAD is unsupported.
    response = session.head(url, timeout=(4, 6), allow_redirects=True)
    if response.status_code in (405, 501):
        response = session.get(url, timeout=(4, 6), allow_redirects=True)

    response.raise_for_status()
    return dict(response.headers)


def run(domain: str) -> Dict:
    """Analyze required security headers and return presence/missing details."""
    result = {
        "status": "success",
        "module": "headers",
        "domain": domain,
        "target_url": "",
        "headers": {},
        "missing_headers": [],
        "error": None,
    }

    try:
        targets = [f"https://{domain}", f"http://{domain}"]
        response_headers = None
        last_error = None

        # Try HTTPS first and fallback to HTTP if needed.
        for target in targets:
            try:
                response_headers = _fetch_headers(target)
                result["target_url"] = target
                break
            except Exception as exc:
                last_error = exc

        if response_headers is None:
            raise RuntimeError(f"Unable to fetch headers: {last_error}")

        analysis = {}
        missing = []
        for header in REQUIRED_HEADERS:
            value = response_headers.get(header)
            present = bool(value)
            if not present:
                missing.append(header)

            analysis[header] = {
                "present": present,
                "value": value if value else "Missing",
            }

        result["headers"] = analysis
        result["missing_headers"] = missing
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result
