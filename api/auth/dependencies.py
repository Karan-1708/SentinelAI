"""
FastAPI dependencies for extracting + authorising the current user.

Usage::

    @router.get("/foo")
    async def foo(user: CurrentUser):
        ...

    @router.patch("/foo", dependencies=[Depends(require_role("admin"))])
    async def edit_foo(...):
        ...
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.security import InvalidTokenError, decode_token
from api.database import get_db
from api.models.user import User

_oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

_ROLE_HIERARCHY: dict[str, int] = {
    "viewer": 10,
    "analyst": 20,
    "admin": 30,
}


async def get_current_user(
    token: Annotated[str | None, Depends(_oauth2)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = decode_token(token)
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    try:
        user_id = uuid.UUID(claims["sub"])
    except (KeyError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token")

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive")
    return user


def require_role(minimum: str):
    """Return a dependency enforcing role >= ``minimum`` in the hierarchy."""
    threshold = _ROLE_HIERARCHY[minimum]

    async def _check(user: Annotated[User, Depends(get_current_user)]) -> User:
        actual = _ROLE_HIERARCHY.get(user.role, 0)
        if actual < threshold:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return _check


CurrentUser = Annotated[User, Depends(get_current_user)]
