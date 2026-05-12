from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class SyslogRecord(BaseModel):
    timestamp: Optional[datetime] = None
    host: Optional[str] = None
    program: Optional[str] = None
    pid: Optional[int] = None
    message: str
    log_source: str = "syslog"
    tags: list[str] = []
