from __future__ import annotations

import uuid
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import CurrentUser, require_role
from api.database import get_db
from api.rate_limit import limiter
from api.schemas.incident import IncidentDetail, IncidentListResponse, IncidentSummary
from api.services import incident_service

router = APIRouter(prefix="/incidents", tags=["incidents"])

_SEVERITY_VALUES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_STATUS_VALUES = ("OPEN", "IN_PROGRESS", "CLOSED")


class StatusUpdate(BaseModel):
    status: Literal["OPEN", "IN_PROGRESS", "CLOSED"]


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    user: CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$"),
    status: Optional[str] = Query(None, pattern="^(OPEN|IN_PROGRESS|CLOSED)$"),
    db: AsyncSession = Depends(get_db),
) -> IncidentListResponse:
    items, total = await incident_service.list_incidents(
        db, page=page, page_size=page_size, severity=severity, status=status
    )
    return IncidentListResponse(
        items=[IncidentSummary.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: uuid.UUID,
    user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> IncidentDetail:
    incident = await incident_service.get_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentDetail.model_validate(incident)


@router.patch(
    "/{incident_id}/status",
    dependencies=[Depends(require_role("analyst"))],
)
@limiter.limit("60/minute")
async def update_status(
    request: Request,
    incident_id: uuid.UUID,
    payload: StatusUpdate,
    db: AsyncSession = Depends(get_db),
) -> dict:
    incident = await incident_service.update_status(db, incident_id, payload.status)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"id": str(incident.id), "status": incident.status}
