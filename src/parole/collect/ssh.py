from __future__ import annotations

from parole.model import SshState
from parole.util import run_cmd, which


def collect_ssh() -> SshState | None:
    if not which("sshd"):
        return SshState(available=False)
    code, raw = run_cmd(["sshd", "-T"])
    if code != 0:
        return SshState(available=False)
    kv = parse_sshd_t(raw)
    return SshState(
        permit_root_login=kv.get("permitrootlogin", ""),
        password_authentication=kv.get("passwordauthentication", ""),
        pubkey_authentication=kv.get("pubkeyauthentication", ""),
        port=kv.get("port", "22"),
        available=True,
    )


def parse_sshd_t(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in raw.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            out[parts[0].lower()] = parts[1].strip().lower()
    return out
