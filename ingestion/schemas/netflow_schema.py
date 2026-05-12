from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class NetflowRecord(BaseModel):
    timestamp: Optional[datetime] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    bytes: Optional[int] = None
    packets: Optional[int] = None
    flow_duration_ms: Optional[float] = None
    log_source: str = "netflow"
    tags: list[str] = []
