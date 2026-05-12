from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class IngestPayload(BaseModel):
    """Incoming log event for prediction."""
    features: dict[str, float] = Field(
        ...,
        description="Feature name → value map. Must cover the 78 CICIDS-2017 features.",
    )
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    log_source: str = "api"
