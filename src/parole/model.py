from __future__ import annotations

from dataclasses import asdict, dataclass, field


SCHEMA_VERSION = 1

# Misma filosofía que Hoztage: 22 abierto NO es drift por sí solo.
SENSITIVE_PORTS = frozenset(
    {
        21, 23, 25, 3306, 5432, 6379, 27017, 9200, 2375, 2376,
        8080, 8443, 10000, 2082, 2083, 2086, 2087,
    }
)

PUBLIC_ADDRS = frozenset({"*", "0.0.0.0", "::", "[::]"})


@dataclass
class ListenerHit:
    port: int
    address: str
    process: str = ""

    def key(self) -> str:
        return f"{self.port}/{self.address}"

    def label(self) -> str:
        proc = f" ({self.process})" if self.process else ""
        return f"{self.address}:{self.port}{proc}"


@dataclass
class SshState:
    permit_root_login: str = ""
    password_authentication: str = ""
    pubkey_authentication: str = ""
    port: str = ""
    available: bool = False


@dataclass
class Snapshot:
    version: int = SCHEMA_VERSION
    hostname: str = ""
    collected_at: str = ""
    platform: str = ""
    linux: bool = True
    listeners: list[ListenerHit] = field(default_factory=list)
    ssh: SshState = field(default_factory=SshState)
    docker_publishes: list[str] = field(default_factory=list)
    ufw: str | None = None  # "active" | "inactive" | None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Snapshot:
        ssh_raw = data.get("ssh") or {}
        ssh = SshState(
            permit_root_login=str(ssh_raw.get("permit_root_login") or ""),
            password_authentication=str(ssh_raw.get("password_authentication") or ""),
            pubkey_authentication=str(ssh_raw.get("pubkey_authentication") or ""),
            port=str(ssh_raw.get("port") or ""),
            available=bool(ssh_raw.get("available")),
        )
        listeners = []
        for row in data.get("listeners") or []:
            if not isinstance(row, dict):
                continue
            try:
                port = int(row.get("port"))
            except (TypeError, ValueError):
                continue
            listeners.append(
                ListenerHit(
                    port=port,
                    address=str(row.get("address") or ""),
                    process=str(row.get("process") or ""),
                )
            )
        return cls(
            version=int(data.get("version") or SCHEMA_VERSION),
            hostname=str(data.get("hostname") or ""),
            collected_at=str(data.get("collected_at") or ""),
            platform=str(data.get("platform") or ""),
            linux=bool(data.get("linux", True)),
            listeners=listeners,
            ssh=ssh,
            docker_publishes=[str(x) for x in (data.get("docker_publishes") or [])],
            ufw=data.get("ufw"),
        )


@dataclass
class Drift:
    id: str
    title: str
    before: str
    after: str
    remediate: list[str] = field(default_factory=list)  # IDs Hozfix (HOZ-...), si mapea
