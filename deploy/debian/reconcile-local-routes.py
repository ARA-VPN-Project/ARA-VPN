#!/usr/bin/env python3
"""Reconcile dedicated ports for active links to locally configured foreign exits."""

import fcntl
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import time


def write_json(path, data):
    old = path.stat() if path.exists() else None
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
            if old:
                os.fchown(f.fileno(), old.st_uid, old.st_gid)
            os.fchmod(f.fileno(), (old.st_mode & 0o777) if old else 0o644)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def main():
    cfg_path = Path(os.environ["ARA_ROUTE_CONFIG"])
    ready_path = Path(os.environ["ARA_ROUTE_READY_FILE"])
    db_path = Path(os.environ["ARA_ROUTE_DB"])
    addr, edge, tls_name = (os.environ[k] for k in ("ARA_ROUTE_BIND", "ARA_ROUTE_EDGE", "ARA_ROUTE_TLS_NAME"))
    unit = os.environ["ARA_ROUTE_UNIT"]

    def firewall(port, remove=False):
        verb = ["--force", "delete"] if remove else []
        cmd = ["ufw", *verb, "allow", "in", "to", addr, "port", str(port), "proto", "tcp"]
        if not remove:
            cmd += ["comment", "ARA managed route"]
        subprocess.run(cmd, check=True)

    def restart():
        subprocess.run(["systemctl", "restart", unit], check=True, timeout=20)

    def check(routes):
        context = ssl.create_default_context()
        for port in routes.values():
            for attempt in range(8):
                try:
                    with socket.create_connection((addr, port), timeout=2) as conn:
                        with context.wrap_socket(conn, server_hostname=tls_name):
                            break
                except OSError:
                    if attempt == 7:
                        raise
                    time.sleep(0.5)

    ready_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with (ready_path.parent / "lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cfg = json.loads(cfg_path.read_text())
        old = dict(cfg)
        foreign = {e["id"] for e in cfg["exits"] if e["role"] == "foreign"}
        with sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=3) as db:
            rows = db.execute("""SELECT DISTINCT l.exit_id,r.port FROM links l
                JOIN route_ports r ON r.edge_node_id=l.edge_id AND r.node_id=l.exit_id
                JOIN nodes n ON n.id=l.exit_id AND n.revoked_at IS NULL
                WHERE l.edge_id=? AND l.revoked_at IS NULL""", (edge,))
            desired = {node: port for node, port in rows if node in foreign and 40000 <= port <= 63999}
        routes = [r for r in cfg.get("routes", []) if r["exit_id"] not in foreign]
        routes += [{"exit_id": n, "listen": f"{addr}:{p}"} for n, p in sorted(desired.items())]
        current = {r["exit_id"]: int(r["listen"].rsplit(":", 1)[1])
                   for r in cfg.get("routes", []) if r["exit_id"] in foreign}
        ready = json.loads(ready_path.read_text()) if ready_path.exists() else {}
        if current == desired and ready == desired:
            return
        new_ports = set(desired.values()) - set(ready.values())
        added = []
        changed = current != desired
        try:
            for port in sorted(new_ports):
                firewall(port)
                added.append(port)
            if changed:
                cfg["routes"] = routes
                write_json(cfg_path, cfg)
                restart()
            check(desired)
            for port in sorted(set(ready.values()) - set(desired.values())):
                firewall(port, remove=True)
            write_json(ready_path, desired)
        except Exception:
            if changed:
                write_json(cfg_path, old)
                restart()
            for port in added:
                if port not in current.values():
                    firewall(port, remove=True)
            raise


if __name__ == "__main__":
    main()
