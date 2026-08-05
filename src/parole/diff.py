from __future__ import annotations

from parole.hozfix_map import remediate_ids
from parole.model import Drift, Snapshot


def diff_snapshots(baseline: Snapshot, current: Snapshot) -> list[Drift]:
    drifts: list[Drift] = []
    drifts.extend(_diff_listeners(baseline, current))
    drifts.extend(_diff_ssh(baseline, current))
    drifts.extend(_diff_docker(baseline, current))
    drifts.extend(_diff_ufw(baseline, current))
    return drifts


def _drift(id: str, title: str, before: str, after: str) -> Drift:
    return Drift(
        id=id,
        title=title,
        before=before,
        after=after,
        remediate=remediate_ids(id, after=after),
    )


def _diff_listeners(base: Snapshot, cur: Snapshot) -> list[Drift]:
    base_ports = {h.port for h in base.listeners}
    cur_by_port = {h.port: h for h in cur.listeners}
    out: list[Drift] = []
    for port, hit in sorted(cur_by_port.items()):
        if port not in base_ports:
            out.append(
                _drift(
                    f"HOZ-DRIFT-NET-{port}",
                    f"Listener público nuevo en {port}",
                    "(no estaba)",
                    hit.label(),
                )
            )
    return out


def _diff_ssh(base: Snapshot, cur: Snapshot) -> list[Drift]:
    if not base.ssh.available and not cur.ssh.available:
        return []
    out: list[Drift] = []
    b, c = base.ssh, cur.ssh

    if _ssh_worse_root(b.permit_root_login, c.permit_root_login):
        out.append(
            _drift(
                "HOZ-DRIFT-SSH-ROOT",
                "PermitRootLogin empeoró",
                b.permit_root_login or "(vacío)",
                c.permit_root_login or "(vacío)",
            )
        )

    if _ssh_worse_password(b.password_authentication, c.password_authentication):
        out.append(
            _drift(
                "HOZ-DRIFT-SSH-PASS",
                "PasswordAuthentication empeoró",
                b.password_authentication or "(vacío)",
                c.password_authentication or "(vacío)",
            )
        )

    if _ssh_worse_pubkey(b.pubkey_authentication, c.pubkey_authentication):
        out.append(
            _drift(
                "HOZ-DRIFT-SSH-PUBKEY",
                "PubkeyAuthentication se apagó",
                b.pubkey_authentication or "(vacío)",
                c.pubkey_authentication or "(vacío)",
            )
        )

    bp = (b.port or "").strip()
    cp = (c.port or "").strip()
    if bp and cp and bp != cp:
        out.append(
            _drift(
                "HOZ-DRIFT-SSH-PORT",
                "Puerto SSH cambió",
                bp,
                cp,
            )
        )
    return out


def _ssh_worse_root(before: str, after: str) -> bool:
    b, a = before.lower(), after.lower()
    if not a or b == a:
        return False
    if a == "yes" and b != "yes":
        return True
    return False


def _ssh_worse_password(before: str, after: str) -> bool:
    b, a = before.lower(), after.lower()
    if not a or b == a:
        return False
    return a == "yes" and b != "yes"


def _ssh_worse_pubkey(before: str, after: str) -> bool:
    b, a = before.lower(), after.lower()
    if not a or b == a:
        return False
    return a == "no" and b != "no"


def _diff_docker(base: Snapshot, cur: Snapshot) -> list[Drift]:
    base_set = set(x.strip() for x in base.docker_publishes)
    out: list[Drift] = []
    for line in cur.docker_publishes:
        line = line.strip()
        if line and line not in base_set:
            name = line.split("\t", 1)[0] if "\t" in line else line.split()[0]
            out.append(
                _drift(
                    "HOZ-DRIFT-DOCK",
                    f"Docker publish público nuevo ({name})",
                    "(no estaba)",
                    line,
                )
            )
    return out


def _diff_ufw(base: Snapshot, cur: Snapshot) -> list[Drift]:
    if base.ufw is None and cur.ufw is None:
        return []
    if base.ufw == cur.ufw:
        return []
    if base.ufw == "active" and cur.ufw == "inactive":
        return [
            _drift(
                "HOZ-DRIFT-UFW",
                "UFW se apagó",
                base.ufw,
                cur.ufw or "(ausente)",
            )
        ]
    if base.ufw == "active" and cur.ufw is None:
        return [
            _drift(
                "HOZ-DRIFT-UFW",
                "UFW ya no está",
                base.ufw,
                "(ausente)",
            )
        ]
    return []
