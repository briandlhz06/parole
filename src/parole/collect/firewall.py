from __future__ import annotations

from parole.util import run_cmd, which


def collect_ufw() -> str | None:
    if not which("ufw"):
        return None
    code, raw = run_cmd(["ufw", "status"])
    if code != 0:
        return None
    low = (raw or "").lower()
    if "status: active" in low:
        return "active"
    if "status: inactive" in low:
        return "inactive"
    return None
