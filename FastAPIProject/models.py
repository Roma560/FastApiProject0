from sqlalchemy import Column, Integer, String, Enum, ForeignKey, DateTime, Boolean, Index, Text
from sqlalchemy.orm import relationship
import enum
import datetime
from database import Base

class UserRole(enum.Enum):
    admin = "admin"
    client = "client"

class MessageStatus(enum.Enum):
    sent = "sent"
    delivered = "delivered"
    read = "read"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.client)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, default=True)

class PsychicProfile(Base):
    __tablename__ = "psychic_profiles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    avatar_url = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, default=True)

class Chat(Base):
    __tablename__ = "chats"
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    psychic_profile_id = Column(Integer, ForeignKey("psychic_profiles.id"), nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_message_at = Column(DateTime, nullable=True)

    client = relationship("User")
    psychic_profile = relationship("PsychicProfile")
    
    __table_args__ = (
        Index('idx_client_active', 'client_id', 'is_active'),
    )

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False, index=True)
    sender = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    status = Column(Enum(MessageStatus), default=MessageStatus.sent)
    read_at = Column(DateTime, nullable=True)

    chat = relationship("Chat")
    
    __table_args__ = (
        Index('idx_chat_timestamp', 'chat_id', 'timestamp'),
        Index('idx_chat_status', 'chat_id', 'status'),
    )




