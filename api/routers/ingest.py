from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from api.auth.dependencies import CurrentUser
from api.rate_limit import limiter
from api.schemas.ingest import IngestPayload

router = APIRouter(prefix="/ingest", tags=["ingest"])


class IngestResponse(BaseModel):
    status: str
    message: str


@router.post("", response_model=IngestResponse)
@limiter.limit("60/minute")
async def ingest(
    request: Request,
    payload: IngestPayload,
    user: CurrentUser,
) -> IngestResponse:
    """
    Validate a log event and acknowledge it. Actual model inference happens on
    POST /predict; this endpoint exists for clients that want a cheap admission
    check without paying for a full prediction round-trip.
    """
    if not payload.features:
        return IngestResponse(status="error", message="Empty features dict")
    return IngestResponse(
        status="accepted",
        message=f"Received {len(payload.features)} features from {payload.log_source}",
    )
