from __future__ import annotations

import math
from typing import Optional

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

# Reject payloads that could exhaust memory. CICIDS-2017 uses 78 features;
# 256 gives generous headroom for new derived features without becoming a
# DoS vector.
_MAX_FEATURES = 256
_MAX_KEY_LEN = 64
_ABS_LIMIT = 1e12


class IngestPayload(BaseModel):
    """Incoming log event for prediction."""

    features: dict[str, float] = Field(
        ...,
        max_length=_MAX_FEATURES,
        description=f"Feature name → value map. Capped at {_MAX_FEATURES} entries.",
    )
    source_ip: Optional[IPvAnyAddress] = None
    dest_ip: Optional[IPvAnyAddress] = None
    log_source: str = Field(default="api", max_length=64)

    @field_validator("features", mode="before")
    @classmethod
    def _validate_features(cls, value: object) -> dict[str, float]:
        # ``mode="before"`` runs before Pydantic's type coercion, so we still
        # see raw JSON booleans (which would otherwise be quietly cast to
        # 1.0/0.0) and can reject them here.
        if not isinstance(value, dict):
            raise ValueError("features must be a JSON object")
        if len(value) > _MAX_FEATURES:
            raise ValueError(f"features may not contain more than {_MAX_FEATURES} entries")
        cleaned: dict[str, float] = {}
        for key, val in value.items():
            if not isinstance(key, str) or not key or len(key) > _MAX_KEY_LEN:
                raise ValueError(f"Feature key length must be 1..{_MAX_KEY_LEN}")
            if isinstance(val, bool):
                raise ValueError(f"Feature {key!r} must be numeric, not bool")
            if not isinstance(val, (int, float)):
                raise ValueError(f"Feature {key!r} must be numeric")
            fval = float(val)
            if math.isnan(fval) or math.isinf(fval):
                raise ValueError(f"Feature {key!r} must be finite")
            if abs(fval) > _ABS_LIMIT:
                raise ValueError(f"Feature {key!r} magnitude exceeds {_ABS_LIMIT}")
            cleaned[key] = fval
        return cleaned

    def source_ip_str(self) -> Optional[str]:
        return str(self.source_ip) if self.source_ip is not None else None

    def dest_ip_str(self) -> Optional[str]:
        return str(self.dest_ip) if self.dest_ip is not None else None
