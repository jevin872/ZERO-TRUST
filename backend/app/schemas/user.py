from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import List, Optional

class RoleResponse(BaseModel):
    id: int
    name: str

    class Config:
        from_attributes = True

class UserBase(BaseModel):
    username: str
    email: EmailStr
    organization_id: Optional[str] = "DEMO_BANK"

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    is_blocked: bool
    blocked_until: Optional[datetime] = None
    created_at: datetime
    roles: List[RoleResponse] = []

    class Config:
        from_attributes = True

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None
