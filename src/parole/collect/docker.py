from __future__ import annotations

from parole.util import run_cmd, which


def collect_public_publishes() -> list[str]:
    if not which("docker"):
        return []
    code, ps = run_cmd(
        ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"]
    )
    if code != 0:
        return []
    out: list[str] = []
    for line in (ps or "").splitlines():
        if "0.0.0.0:" in line or ":::" in line:
            out.append(line.strip())
    return out


def publish_keys(lines: list[str]) -> set[str]:
    """Normalize docker publish lines for set comparison."""
    keys: set[str] = set()
    for line in lines:
        keys.add(line.strip())
    return keys
