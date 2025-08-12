from datetime import datetime
from pydantic import BaseModel
from typing import Optional
from models import UserRole, MessageStatus


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


class PsychicProfileUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    avatar_url: Optional[str] = None


class ChatCreate(BaseModel):
    psychic_profile_id: int


class ChatResponse(BaseModel):
    id: int
    client_id: int
    psychic_profile_id: int
    is_active: int

    class Config:
        from_attributes = True


class MessageCreate(BaseModel):
    chat_id: int
    content: str


class MessageResponse(BaseModel):
    id: int
    chat_id: int
    sender: str
    content: str
    timestamp: datetime
    status: MessageStatus
    read_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class MessageStatusUpdate(BaseModel):
    status: MessageStatus

