from __future__ import annotations

import re

from parole.model import PUBLIC_ADDRS, SENSITIVE_PORTS, ListenerHit
from parole.util import run_cmd, which


def collect_sensitive_public() -> list[ListenerHit]:
    raw = _listen_raw()
    if not raw:
        return []
    hits: list[ListenerHit] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        if not line or line.lower().startswith(("netid", "proto", "active")):
            continue
        ep = _local_endpoint(line)
        if not ep:
            continue
        addr, port = ep
        if port not in SENSITIVE_PORTS:
            continue
        if not _is_public(addr):
            continue
        hit = ListenerHit(port=port, address=_norm_addr(addr), process=_process(line))
        if hit.key() in seen:
            continue
        seen.add(hit.key())
        hits.append(hit)
    hits.sort(key=lambda h: (h.port, h.address))
    return hits


def _listen_raw() -> str:
    if which("ss"):
        code, raw = run_cmd(["ss", "-tulpn"])
        return raw if code == 0 else ""
    if which("netstat"):
        code, raw = run_cmd(["netstat", "-tulpn"])
        return raw if code == 0 else ""
    return ""


def _is_public(addr: str) -> bool:
    a = addr.lower().strip("[]")
    if a in {"127.0.0.1", "::1", "localhost"}:
        return False
    if a in PUBLIC_ADDRS or a in {"*", "0.0.0.0", "::"}:
        return True
    if a.startswith("127."):
        return False
    return True


def _norm_addr(addr: str) -> str:
    a = addr.lower()
    if a in {"*", "[::]", "::"}:
        return "0.0.0.0" if a == "*" else "::"
    return a.strip("[]") if a.startswith("[") else a


def _process(line: str) -> str:
    m = re.search(r'users:\(\("([^"]+)"', line)
    if m:
        return m.group(1)
    m = re.search(r"/([^/\s]+)\s*$", line)
    return m.group(1) if m else ""


def _local_endpoint(line: str) -> tuple[str, int] | None:
    m = re.search(
        r"(?P<host>\*|0\.0\.0\.0|127\.0\.0\.1|\[::\]|\[::1\]|::|localhost):(?P<port>\d+)\b",
        line,
        re.I,
    )
    if m:
        return m.group("host").lower(), int(m.group("port"))
    m = re.search(r"\s(\*|\[[^\]]+\]|[\d.]+):(\d+)\s", line)
    if m:
        return m.group(1).lower(), int(m.group(2))
    return None


def parse_ss_lines(raw: str) -> list[ListenerHit]:
    """Helper for tests: parse ss/netstat-like text into sensitive public hits."""
    hits: list[ListenerHit] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        if not line or line.lower().startswith(("netid", "proto", "active")):
            continue
        ep = _local_endpoint(line)
        if not ep:
            continue
        addr, port = ep
        if port not in SENSITIVE_PORTS or not _is_public(addr):
            continue
        hit = ListenerHit(port=port, address=_norm_addr(addr), process=_process(line))
        if hit.key() in seen:
            continue
        seen.add(hit.key())
        hits.append(hit)
    return hits
