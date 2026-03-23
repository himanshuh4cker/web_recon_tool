"""Subdomain discovery module using crt.sh and DNS brute force."""

from __future__ import annotations

import concurrent.futures
import random
import re
import socket
import string
from pathlib import Path
from typing import Dict, List, Set


HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+$")


def _is_valid_target_hostname(candidate: str, target_domain: str) -> bool:
    """Return True only for valid hostnames that belong to the target domain."""
    if not candidate:
        return False

    if " " in candidate or "_" in candidate:
        return False

    if not HOSTNAME_RE.match(candidate):
        return False

    if ".." in candidate or candidate.startswith(".") or candidate.endswith("."):
        return False

    target = target_domain.lower()
    if candidate != target and not candidate.endswith(f".{target}"):
        return False

    labels = candidate.split(".")
    for label in labels:
        if not label:
            return False
        if len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def _normalize_subdomain(raw_name: str, target_domain: str) -> str:
    """Normalize a subdomain candidate from certificate data."""
    # Remove wildcard prefix and normalize case for consistent deduplication.
    clean = raw_name.replace("*.", "").strip().lower().rstrip(".")
    if _is_valid_target_hostname(clean, target_domain):
        return clean
    return ""


def enumerate_crtsh(domain: str, timeout: int = 15) -> Dict:
    """Fetch subdomains for a target from crt.sh public certificate transparency API."""
    result = {
        "status": "success",
        "source": "crt.sh",
        "domain": domain,
        "subdomains": [],
        "count": 0,
        "error": None,
    }

    try:
        import requests

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()

        raw_entries = response.json()
        discovered: Set[str] = set()

        for entry in raw_entries:
            # crt.sh may contain several names in one field split by newlines.
            name_value = str(entry.get("name_value", ""))
            for item in name_value.splitlines():
                candidate = _normalize_subdomain(item, domain)
                if candidate:
                    discovered.add(candidate)

        result["subdomains"] = sorted(discovered)
        result["count"] = len(result["subdomains"])
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result


def _resolve_subdomain(hostname: str) -> Dict:
    """Resolve one candidate hostname to validate it exists in DNS."""
    try:
        ip_address = socket.gethostbyname(hostname)
        return {"hostname": hostname, "ip": ip_address, "resolved": True}
    except Exception:
        return {"hostname": hostname, "ip": None, "resolved": False}


def _detect_wildcard_dns(domain: str, probes: int = 4) -> Dict:
    """Detect wildcard DNS by resolving random unlikely hostnames for the same domain."""
    resolved_ips: Set[str] = set()
    resolved_count = 0

    for _ in range(probes):
        random_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        hostname = f"{random_label}.{domain}"
        try:
            ip_address = socket.gethostbyname(hostname)
            resolved_count += 1
            resolved_ips.add(ip_address)
        except Exception:
            continue

    # Two or more successful random resolutions strongly indicate wildcard DNS behavior.
    wildcard_detected = resolved_count >= 2
    return {
        "wildcard_detected": wildcard_detected,
        "resolved_random_hosts": resolved_count,
        "wildcard_ips": sorted(resolved_ips),
    }


def dns_bruteforce(domain: str, wordlist_path: str, max_workers: int = 30) -> Dict:
    """Perform threaded DNS brute force using words from a local wordlist file."""
    result = {
        "status": "success",
        "source": "dns_bruteforce",
        "domain": domain,
        "subdomains": [],
        "count": 0,
        "wildcard_detected": False,
        "wildcard_ips": [],
        "note": "",
        "error": None,
    }

    try:
        path = Path(wordlist_path)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        # Read candidate labels and ignore empty lines/comments.
        words: List[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)

        wildcard_info = _detect_wildcard_dns(domain)
        result["wildcard_detected"] = wildcard_info["wildcard_detected"]
        result["wildcard_ips"] = wildcard_info["wildcard_ips"]

        if wildcard_info["wildcard_detected"]:
            # Skip brute-force output when wildcard DNS is enabled to avoid false positives.
            result["note"] = (
                "Wildcard DNS detected. DNS brute-force results were skipped to prevent false positives."
            )
            return result

        hostnames = [f"{word}.{domain}" for word in words]
        found = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_resolve_subdomain, hostname) for hostname in hostnames]
            for future in concurrent.futures.as_completed(futures):
                response = future.result()
                if response["resolved"]:
                    found.append(response)

        found.sort(key=lambda item: item["hostname"])
        result["subdomains"] = found
        result["count"] = len(found)
        result["note"] = "DNS brute-force completed without wildcard DNS indicators."
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result


def run(domain: str, wordlist_path: str) -> Dict:
    """Run all subdomain discovery methods and return combined structured output."""
    output = {
        "status": "success",
        "module": "subdomain",
        "domain": domain,
        "crtsh": {},
        "dns_bruteforce": {},
        "unique_subdomains": [],
        "count": 0,
        "note": "",
        "error": None,
    }

    try:
        crt_result = enumerate_crtsh(domain)
        brute_result = dns_bruteforce(domain, wordlist_path)

        unique = set(crt_result.get("subdomains", []))
        for item in brute_result.get("subdomains", []):
            unique.add(item["hostname"])

        output["crtsh"] = crt_result
        output["dns_bruteforce"] = brute_result
        output["unique_subdomains"] = sorted(unique)
        output["count"] = len(output["unique_subdomains"])

        if brute_result.get("wildcard_detected"):
            output["note"] = (
                "Wildcard DNS detected for target. Unique subdomain list prioritizes crt.sh entries."
            )

        if crt_result.get("status") == "error" and brute_result.get("status") == "error":
            output["status"] = "error"
            output["error"] = "Both crt.sh enumeration and DNS brute force failed"
    except Exception as exc:
        output["status"] = "error"
        output["error"] = str(exc)

    return output
