from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import require_role
from api.auth.security import create_access_token, hash_password, verify_password
from api.config import settings
from api.database import get_db
from api.models.user import User
from api.rate_limit import limiter
from api.schemas.auth import TokenResponse, UserCreate, UserPublic

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """Exchange email + password for a short-lived JWT."""
    result = await db.execute(select(User).where(User.email == form.username))
    user = result.scalar_one_or_none()

    # Constant-ish response: always verify a hash to avoid timing side-channels
    # that reveal whether an email exists in the users table.
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    hashed = user.hashed_password if user else dummy_hash
    password_ok = verify_password(form.password, hashed)

    if not user or not password_ok or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(subject=str(user.id), role=user.role)
    return TokenResponse(access_token=token, expires_in=settings.api_access_token_minutes * 60)


@router.post(
    "/register",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role("admin"))],
)
@limiter.limit("10/minute")
async def register(
    request: Request,
    payload: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserPublic:
    """Admin-only user provisioning. Self-signup is intentionally not exposed."""
    user = User(
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    await db.refresh(user)
    return UserPublic.model_validate(user)
