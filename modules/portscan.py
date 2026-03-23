"""Port scanning module using python-nmap."""

from __future__ import annotations

import concurrent.futures
import os
import shutil
import socket
from typing import Dict, List, Sequence


COMMON_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 636, 873, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723, 1883, 2049,
    2375, 2376, 3000, 3128, 3306, 3389, 4444, 5432, 5672, 5900, 5985, 5986,
    6379, 6443, 7001, 7002, 7077, 8000, 8080, 8081, 8088, 8443, 8888, 9000,
    9090, 9200, 9300, 9418, 10000, 11211, 27017,
]


def _scan_config(scan_profile: str) -> Dict:
    """Return scanner settings based on selected profile for speed/coverage balance."""
    mapping = {
        "fast": {"top_ports": 200, "service_detection": False},
        "balanced": {"top_ports": 500, "service_detection": True},
        "deep": {"top_ports": 1000, "service_detection": True},
    }
    return mapping.get(scan_profile, mapping["fast"])


def _find_nmap_search_paths() -> Sequence[str]:
    """Find nmap binary in common system paths so PATH customization is not required."""
    candidates = [
        shutil.which("nmap"),
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/snap/bin/nmap",
        "/opt/homebrew/bin/nmap",
    ]
    valid_paths = []
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            valid_paths.append(candidate)
    # Return deduplicated paths while preserving order.
    return tuple(dict.fromkeys(valid_paths))


def _socket_probe(target_ip: str, port: int, timeout: float) -> Dict:
    """Try connecting to one TCP port; used as fallback when nmap binary is unavailable."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        status = sock.connect_ex((target_ip, port))
        if status == 0:
            try:
                service_name = socket.getservbyport(port, "tcp")
            except Exception:
                service_name = "unknown"
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service_name,
                "product": "",
                "version": "",
                "extrainfo": "socket-fallback",
            }
    finally:
        sock.close()

    return {}


def _socket_fallback_scan(domain: str, top_ports: int) -> Dict:
    """Run a threaded TCP connect scan over common ports as a no-nmap fallback path."""
    target_ip = socket.gethostbyname(domain)
    scan_ports = COMMON_PORTS[:top_ports] if top_ports <= len(COMMON_PORTS) else COMMON_PORTS
    open_ports: List[Dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(_socket_probe, target_ip, port, 0.7) for port in scan_ports]
        for future in concurrent.futures.as_completed(futures):
            item = future.result()
            if item:
                item["host"] = target_ip
                open_ports.append(item)

    open_ports.sort(key=lambda p: int(p.get("port", 0)))
    return {
        "scanner": "socket-fallback",
        "host": target_ip,
        "open_ports": open_ports,
    }


def run(domain: str, scan_profile: str = "fast") -> Dict:
    """Scan ports and return structured findings, with nmap fallback when unavailable."""
    config = _scan_config(scan_profile)
    result = {
        "status": "success",
        "module": "portscan",
        "domain": domain,
        "scan_profile": scan_profile,
        "scanner": "nmap",
        "open_ports": [],
        "count": 0,
        "note": "",
        "error": None,
    }

    try:
        try:
            import nmap  # type: ignore
        except Exception:
            nmap = None

        nmap_paths = _find_nmap_search_paths()
        if nmap is None or not nmap_paths:
            fallback = _socket_fallback_scan(domain, top_ports=config["top_ports"])
            result["scanner"] = fallback["scanner"]
            result["open_ports"] = fallback["open_ports"]
            result["count"] = len(fallback["open_ports"])
            result["note"] = (
                "nmap package/binary not available. Used fast socket fallback scan over common ports. "
                "Install python-nmap and nmap for full top-port and service/version detection."
            )
            return result

        scanner = nmap.PortScanner(nmap_search_path=nmap_paths)

        args = [
            "-Pn",
            "-n",
            "--open",
            f"--top-ports {config['top_ports']}",
            "--max-retries 1",
            "--host-timeout 2m",
            "-T4",
        ]
        if config["service_detection"]:
            # Use lightweight service fingerprinting to reduce runtime overhead.
            args.extend(["-sV", "--version-light"])

        scanner.scan(hosts=domain, arguments=" ".join(args))

        if domain not in scanner.all_hosts():
            # nmap may resolve hostnames differently; use first discovered host if available.
            hosts = scanner.all_hosts()
            if not hosts:
                raise RuntimeError("No hosts were discovered during the scan")
            target_host = hosts[0]
        else:
            target_host = domain

        open_ports: List[Dict] = []
        for protocol in scanner[target_host].all_protocols():
            ports = scanner[target_host][protocol].keys()
            for port in sorted(ports):
                port_info = scanner[target_host][protocol][port]
                if port_info.get("state") == "open":
                    open_ports.append(
                        {
                            "host": target_host,
                            "port": port,
                            "protocol": protocol,
                            "state": port_info.get("state", "unknown"),
                            "service": port_info.get("name", "unknown"),
                            "product": port_info.get("product", ""),
                            "version": port_info.get("version", ""),
                            "extrainfo": port_info.get("extrainfo", ""),
                        }
                    )

        result["open_ports"] = open_ports
        result["count"] = len(open_ports)
    except Exception as exc:
        # If nmap run fails for runtime reasons, fall back to fast socket scanning.
        try:
            fallback = _socket_fallback_scan(domain, top_ports=config["top_ports"])
            result["scanner"] = fallback["scanner"]
            result["open_ports"] = fallback["open_ports"]
            result["count"] = len(fallback["open_ports"])
            result["note"] = f"nmap scan failed, fallback used: {exc}"
        except Exception as fallback_exc:
            result["status"] = "error"
            result["error"] = f"nmap error: {exc}; fallback error: {fallback_exc}"

    return result
