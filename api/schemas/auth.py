from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: Literal["viewer", "analyst", "admin"] = "viewer"


class UserPublic(BaseModel):
    id: uuid.UUID
    email: EmailStr
    role: str
    is_active: bool

    model_config = {"from_attributes": True}
