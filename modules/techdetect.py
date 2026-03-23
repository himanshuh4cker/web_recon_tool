"""Technology detection module using builtwith."""

from __future__ import annotations

import multiprocessing
from typing import Dict


def _builtwith_worker(url: str, queue: multiprocessing.Queue) -> None:
    """Run builtwith parsing in a child process so it can be hard-time-limited."""
    try:
        import builtwith

        queue.put({"status": "success", "data": builtwith.parse(url)})
    except Exception as exc:
        queue.put({"status": "error", "error": str(exc)})


def _parse_with_timeout(url: str, timeout_seconds: int) -> Dict:
    """Parse a URL with builtwith under a strict timeout."""
    ctx = multiprocessing.get_context("fork")
    queue: multiprocessing.Queue = ctx.Queue()
    process = ctx.Process(target=_builtwith_worker, args=(url, queue))
    process.start()
    process.join(timeout=timeout_seconds)

    if process.is_alive():
        process.terminate()
        process.join(2)
        return {"status": "error", "error": f"technology detection timed out after {timeout_seconds}s"}

    if queue.empty():
        return {"status": "error", "error": "technology detection returned no data"}

    return queue.get()


def run(domain: str) -> Dict:
    """Detect web technologies used by the target and return structured output."""
    result = {
        "status": "success",
        "module": "techdetect",
        "domain": domain,
        "target_url": "",
        "technologies": {},
        "error": None,
    }

    try:
        try:
            import builtwith  # noqa: F401
        except Exception as exc:
            raise RuntimeError(f"builtwith is not installed: {exc}")

        # Try HTTPS first; if detection fails, retry over HTTP.
        targets = [f"https://{domain}", f"http://{domain}"]
        last_error = None

        for target in targets:
            parsed = _parse_with_timeout(target, timeout_seconds=25)
            if parsed.get("status") == "success":
                tech = parsed.get("data", {})
                result["target_url"] = target
                result["technologies"] = tech
                return result
            last_error = parsed.get("error", "unknown technology detection error")

        raise RuntimeError(f"Technology detection failed for both HTTP and HTTPS: {last_error}")
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result
