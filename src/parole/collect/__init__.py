from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone

from parole.collect import docker as dock_c
from parole.collect import firewall as fw_c
from parole.collect import net as net_c
from parole.collect import ssh as ssh_c
from parole.model import Snapshot, SshState
from parole.util import is_linux


def take_snapshot() -> Snapshot:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    host = socket.gethostname()
    plat = platform.platform()
    if not is_linux():
        return Snapshot(
            hostname=host,
            collected_at=now,
            platform=plat,
            linux=False,
        )
    return Snapshot(
        hostname=host,
        collected_at=now,
        platform=plat,
        linux=True,
        listeners=net_c.collect_sensitive_public(),
        ssh=ssh_c.collect_ssh() or SshState(),
        docker_publishes=dock_c.collect_public_publishes(),
        ufw=fw_c.collect_ufw(),
    )
