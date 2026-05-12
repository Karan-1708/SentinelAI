from fastapi import APIRouter
from pydantic import BaseModel

from api.schemas.ingest import IngestPayload

router = APIRouter(prefix="/ingest", tags=["ingest"])


class IngestResponse(BaseModel):
    status: str
    message: str


@router.post("", response_model=IngestResponse)
async def ingest(payload: IngestPayload) -> IngestResponse:
    """
    Validate and accept a log event.
    For simple clients that don't need the prediction response immediately —
    the full prediction pipeline runs via POST /predict.
    This endpoint validates the schema and returns immediately.
    """
    if not payload.features:
        return IngestResponse(status="error", message="Empty features dict")
    return IngestResponse(
        status="accepted",
        message=f"Received {len(payload.features)} features from {payload.log_source}",
    )
