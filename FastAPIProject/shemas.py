from pydantic import BaseModel
from typing import Optional
from models import UserRole

class UserCreate(BaseModel):
    username: str
    password: str
    role: UserRole = UserRole.client

class UserResponse(BaseModel):
    id: int
    username: str
    role: UserRole

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class PsychicProfileCreate(BaseModel):
    name: str
    description: Optional[str] = None
    avatar_url: Optional[str] = None

class PsychicProfileResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    avatar_url: Optional[str] = None

