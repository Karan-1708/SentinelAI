"""
Synthetic log generator for demo and testing purposes.

Generates realistic syslog, Windows Event Log, and NetFlow records
at a configurable rate and sends them to Logstash over TCP.

This keeps the React dashboard live feed active during demos without
needing the full 2.8GB CICIDS dataset loaded.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import socket
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Weighted distribution of log types (syslog-heavy, like real environments)
_LOG_TYPE_WEIGHTS = {"syslog": 0.60, "winevent": 0.30, "netflow": 0.10}

# Sample IPs for synthetic events
_INTERNAL_IPS = [f"192.168.1.{i}" for i in range(1, 50)]
_EXTERNAL_IPS = [
    "203.0.113.42", "198.51.100.7", "185.220.101.34",
    "45.83.64.1", "91.108.4.100", "104.21.35.54",
]
_ATTACK_IPS = [
    "10.0.0.1", "172.16.0.5", "192.168.100.200",
    "198.18.0.42", "198.19.0.10",
]

# Syslog attack patterns (mimics real auth.log entries)
_SYSLOG_TEMPLATES = [
    "sshd[{pid}]: Failed password for {user} from {src_ip} port {port} ssh2",
    "sshd[{pid}]: Invalid user {user} from {src_ip} port {port}",
    "sshd[{pid}]: Accepted password for {user} from {src_ip} port {port} ssh2",
    "sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
    "kernel: [UFW BLOCK] IN=eth0 OUT= SRC={src_ip} DST={dst_ip} LEN=40 PROTO=TCP",
    "ftpd[{pid}]: FAIL LOGIN: Client {src_ip}",
    "apache2[{pid}]: {src_ip} - - [{ts}] \"GET /admin HTTP/1.1\" 403 287",
]

# Windows Event IDs of interest
_WIN_EVENT_IDS = [4625, 4625, 4625, 4688, 4697, 4720, 4732, 4624]

# Port scan targets
_SCAN_PORTS = [21, 22, 23, 25, 80, 443, 3389, 8080, 8443, 3306, 5432]


def _syslog_message() -> str:
    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%b %d %H:%M:%S")
    template = random.choice(_SYSLOG_TEMPLATES)
    src_ip = random.choice(_EXTERNAL_IPS + _ATTACK_IPS)
    dst_ip = random.choice(_INTERNAL_IPS)
    user = random.choice(["root", "admin", "ubuntu", "kali", "pi", "test"])
    return (
        f"{ts_str} {random.choice(_INTERNAL_IPS)} "
        + template.format(
            pid=random.randint(1000, 9999),
            user=user,
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=random.randint(1024, 65535),
            ts=now.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        )
    )


def _winevent_message() -> str:
    event_id = random.choice(_WIN_EVENT_IDS)
    src_ip = random.choice(_EXTERNAL_IPS + _ATTACK_IPS)
    user = random.choice(["Administrator", "SYSTEM", "svc_backup", "jdoe"])
    workstation = random.choice(["DESKTOP-ABC123", "LAPTOP-XYZ456", "WKS-FINANCE01"])
    return json.dumps({
        "winlog": {
            "event_id": event_id,
            "channel": "Security",
            "computer_name": workstation,
            "event_data": {
                "IpAddress": src_ip,
                "TargetUserName": user,
                "WorkstationName": workstation,
                "LogonType": random.choice([3, 10]),
            },
        },
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "tags": ["winlogbeat", "synthetic"],
    })


def _netflow_message() -> str:
    src_ip = random.choice(_EXTERNAL_IPS + _ATTACK_IPS)
    dst_ip = random.choice(_INTERNAL_IPS)
    dst_port = random.choice(_SCAN_PORTS)
    # Simulate port scan: many flows, few bytes each
    is_scan = random.random() < 0.3
    packets = random.randint(1, 5) if is_scan else random.randint(100, 50000)
    bytes_count = packets * random.randint(40, 64)
    return json.dumps({
        "netflow": {
            "ipv4_src_addr": src_ip,
            "ipv4_dst_addr": dst_ip,
            "l4_src_port": random.randint(1024, 65535),
            "l4_dst_port": dst_port,
            "protocol": 6,  # TCP
            "in_pkts": packets,
            "in_bytes": bytes_count,
        },
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "tags": ["netflow", "synthetic"],
    })


def _generate_event() -> tuple[str, str]:
    """Return (event_type, message_string) for one synthetic log event."""
    rand = random.random()
    cumulative = 0.0
    for event_type, weight in _LOG_TYPE_WEIGHTS.items():
        cumulative += weight
        if rand < cumulative:
            if event_type == "syslog":
                return event_type, _syslog_message() + "\n"
            elif event_type == "winevent":
                return event_type, _winevent_message() + "\n"
            else:
                return event_type, _netflow_message() + "\n"
    return "syslog", _syslog_message() + "\n"


async def generate_async(
    host: str = "localhost",
    port: int = 5000,
    rate_per_second: float = 10.0,
    max_events: int | None = None,
) -> None:
    """
    Async log generator — sends synthetic events to Logstash TCP input.
    Runs indefinitely unless max_events is set.
    """
    interval = 1.0 / rate_per_second
    count = 0

    reader, writer = await asyncio.open_connection(host, port)
    logger.info("Connected to Logstash at %s:%d — generating at %.1f/sec", host, port, rate_per_second)

    try:
        while max_events is None or count < max_events:
            event_type, message = _generate_event()
            writer.write(message.encode("utf-8"))
            await writer.drain()
            count += 1
            if count % 100 == 0:
                logger.info("Sent %d synthetic events", count)
            await asyncio.sleep(interval)
    finally:
        writer.close()
        await writer.wait_closed()
        logger.info("Generator stopped after %d events", count)


def generate_sync(
    host: str = "localhost",
    port: int = 5000,
    rate_per_second: float = 10.0,
    max_events: int | None = None,
) -> None:
    """Synchronous wrapper around the async generator."""
    asyncio.run(generate_async(host, port, rate_per_second, max_events))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Synthetic log generator")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--rate", type=float, default=10.0, help="Events per second")
    parser.add_argument("--max", type=int, default=None, help="Max events (None = infinite)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    generate_sync(args.host, args.port, args.rate, args.max)
