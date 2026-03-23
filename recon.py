"""Main entry point for the Web Recon Automation Tool."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import time
from pathlib import Path
from typing import Dict

from modules import headers, portscan, subdomain, techdetect, whois_lookup
from modules.report_generator import generate_html_report


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for target domain and output report path."""
    parser = argparse.ArgumentParser(
        description="Web Recon Automation Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain, e.g. example.com")
    parser.add_argument("-o", "--output", help="Output HTML report file path")
    parser.add_argument(
        "-w",
        "--wordlist",
        default="wordlists/subdomains.txt",
        help="Wordlist path for DNS brute force",
    )
    parser.add_argument(
        "--scan-profile",
        choices=["fast", "balanced", "deep"],
        default="fast",
        help="Port scan profile: fast (quicker), balanced, deep (top 1000 + service detection)",
    )
    return parser.parse_args()


def _default_output_path(domain: str) -> str:
    """Build a safe default report filename based on the target domain."""
    safe_name = re.sub(r"[^a-zA-Z0-9.-]", "_", domain).strip("._") or "target"
    return str(Path("reports") / f"{safe_name}.html")


def run_recon(domain: str, wordlist_path: str, scan_profile: str) -> Dict:
    """Run all recon modules in parallel and combine structured outputs."""
    results: Dict = {
        "subdomain": {},
        "portscan": {},
        "techdetect": {},
        "headers": {},
        "whois_lookup": {},
    }

    # Define module tasks to execute in a thread pool for better speed.
    tasks = {
        "subdomain": lambda: subdomain.run(domain, wordlist_path),
        "portscan": lambda: portscan.run(domain, scan_profile=scan_profile),
        "techdetect": lambda: techdetect.run(domain),
        "headers": lambda: headers.run(domain),
        "whois_lookup": lambda: whois_lookup.run(domain),
    }

    def _module_summary(module_name: str, module_result: Dict) -> str:
        """Build a concise verbose summary line for completed modules."""
        if module_name == "subdomain":
            count = module_result.get("count", 0)
            crt_count = module_result.get("crtsh", {}).get("count", 0)
            brute_count = module_result.get("dns_bruteforce", {}).get("count", 0)
            brute_note = module_result.get("dns_bruteforce", {}).get("note", "")
            sample = ", ".join(module_result.get("unique_subdomains", [])[:5])
            base = f"subdomains={count} | crt.sh={crt_count} | dns_bruteforce={brute_count}"
            if brute_note:
                base += f" | note: {brute_note}"
            return base + (f" | sample: {sample}" if sample else "")

        if module_name == "portscan":
            count = module_result.get("count", 0)
            scanner_name = module_result.get("scanner", "unknown")
            top_ports = ", ".join(str(p.get("port")) for p in module_result.get("open_ports", [])[:8])
            note = module_result.get("note")
            base = f"open_ports={count} | scanner={scanner_name}"
            if top_ports:
                base += f" | ports: {top_ports}"
            if note:
                base += f" | note: {note}"
            return base

        if module_name == "headers":
            missing = module_result.get("missing_headers", [])
            return f"missing_headers={len(missing)}" + (f" | {', '.join(missing)}" if missing else " | all required headers present")

        if module_name == "techdetect":
            technologies = module_result.get("technologies", {})
            category_count = len(technologies)
            preview = ", ".join(list(technologies.keys())[:5])
            return f"tech_categories={category_count}" + (f" | categories: {preview}" if preview else "")

        if module_name == "whois_lookup":
            whois_data = module_result.get("whois", {})
            registrar = whois_data.get("registrar", "")
            return f"whois_fields={len(whois_data)}" + (f" | registrar: {registrar}" if registrar else "")

        return "completed"

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
    interrupted = False
    try:
        future_map = {}
        started = {}
        for module_name, func in tasks.items():
            print(f"[+] Starting {module_name} module...")
            future = executor.submit(func)
            future_map[future] = module_name
            started[module_name] = time.time()

        for future in concurrent.futures.as_completed(future_map):
            module_name = future_map[future]
            try:
                module_result = future.result()
                results[module_name] = module_result
                elapsed = time.time() - started.get(module_name, time.time())
                if module_result.get("status") == "success":
                    print(f"[+] Completed {module_name} module in {elapsed:.1f}s")
                    print(f"    [=] { _module_summary(module_name, module_result) }")
                else:
                    print(f"[!] {module_name} module completed with errors in {elapsed:.1f}s: {module_result.get('error')}")
            except Exception as exc:
                print(f"[!] {module_name} module crashed: {exc}")
                results[module_name] = {
                    "status": "error",
                    "module": module_name,
                    "error": str(exc),
                }
    except KeyboardInterrupt:
        interrupted = True
        print("\n[!] KeyboardInterrupt received, canceling pending modules...")
        for future in future_map:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        # Keep normal flow clean and avoid thread-shutdown noise on manual interruption.
        if not interrupted:
            executor.shutdown(wait=True, cancel_futures=False)

    return results


def save_report(report_html: str, output_path: str) -> None:
    """Save generated HTML report to disk, creating parent folders when needed."""
    path = Path(output_path)
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_html, encoding="utf-8")


def main() -> None:
    """CLI workflow: parse input, execute recon modules, and write output report."""
    args = parse_args()
    output_path = args.output if args.output else _default_output_path(args.domain)

    print(f"\n[*] Running web recon for: {args.domain}")
    print(f"[*] Port scan profile: {args.scan_profile}")
    print(f"[*] Output report: {output_path}")
    print("[*] This may take some time depending on network conditions and target response speed.\n")

    findings = run_recon(args.domain, args.wordlist, args.scan_profile)

    report_html = generate_html_report(args.domain, findings)
    save_report(report_html, output_path)

    # Save raw JSON findings alongside the HTML report for machine-readable consumption.
    json_path = str(Path(output_path).with_suffix(".json"))
    Path(json_path).write_text(json.dumps(findings, indent=2), encoding="utf-8")

    print("\n[+] Recon completed")
    print(f"[+] HTML report saved to: {output_path}")
    print(f"[+] JSON findings saved to: {json_path}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user")
    except Exception as exc:
        print(f"\n[!] Fatal error: {exc}")
