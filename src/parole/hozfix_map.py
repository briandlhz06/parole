from __future__ import annotations

import re

# Misma tabla que Hoztage ID_BY_PORT → finding HOZ-NET-NNN.
NET_PORT_TO_ID: dict[int, str] = {
    21: "HOZ-NET-001",
    23: "HOZ-NET-002",
    25: "HOZ-NET-003",
    3306: "HOZ-NET-004",
    5432: "HOZ-NET-005",
    6379: "HOZ-NET-006",
    27017: "HOZ-NET-007",
    9200: "HOZ-NET-008",
    2375: "HOZ-NET-009",
    2376: "HOZ-NET-010",
    8080: "HOZ-NET-011",
    8443: "HOZ-NET-012",
    10000: "HOZ-NET-013",
    2082: "HOZ-NET-014",
    2083: "HOZ-NET-015",
    2086: "HOZ-NET-016",
    2087: "HOZ-NET-017",
}

SSH_DRIFT_TO_ID: dict[str, str] = {
    "HOZ-DRIFT-SSH-ROOT": "HOZ-SSH-001",
    "HOZ-DRIFT-SSH-PASS": "HOZ-SSH-002",
    "HOZ-DRIFT-SSH-PUBKEY": "HOZ-SSH-003",
    "HOZ-DRIFT-SSH-PORT": "HOZ-SSH-005",
}

# Puertos Docker "malos" de Hoztage (HOZ-DOCK-{port}); el resto → HOZ-DOCK-010.
DOCKER_BAD_PORTS = frozenset({"3306", "5432", "6379", "27017", "2375"})

_NET_DRIFT_RE = re.compile(r"^HOZ-DRIFT-NET-(\d+)$")
_DOCKER_PUB_RE = re.compile(r"(?:0\.0\.0\.0|:::):(\d+)->")


def remediate_ids(drift_id: str, *, after: str = "") -> list[str]:
    """IDs de Hozfix reales para este drift. Vacío si no hay mapeo."""
    m = _NET_DRIFT_RE.match(drift_id)
    if m:
        port = int(m.group(1))
        hid = NET_PORT_TO_ID.get(port)
        return [hid] if hid else []

    if drift_id in SSH_DRIFT_TO_ID:
        return [SSH_DRIFT_TO_ID[drift_id]]

    if drift_id == "HOZ-DRIFT-UFW":
        return ["HOZ-FW-001"]

    if drift_id == "HOZ-DRIFT-DOCK":
        return _docker_ids(after)

    return []


def _docker_ids(after: str) -> list[str]:
    ports = _DOCKER_PUB_RE.findall(after or "")
    bad = [p for p in ports if p in DOCKER_BAD_PORTS]
    if bad:
        # estable y sin dupes
        seen: list[str] = []
        for p in bad:
            fid = f"HOZ-DOCK-{p}"
            if fid not in seen:
                seen.append(fid)
        return seen
    return ["HOZ-DOCK-010"]


def unique_remediate(drifts: list) -> list[str]:
    """Lista ordenada de IDs Hozfix únicos entre drifts."""
    seen: list[str] = []
    for d in drifts:
        for hid in getattr(d, "remediate", None) or []:
            if hid and hid not in seen:
                seen.append(hid)
    return seen


def hozfix_command(ids: list[str]) -> str | None:
    if not ids:
        return None
    return f"python -m hozfix --ids {','.join(ids)}"
