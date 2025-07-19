from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List

from models import User, UserRole
from shemas import UserCreate, UserResponse, Token
from auth import hash_password, verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from database import SessionLocal, engine
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta

app = FastAPI()

def get_db() -> SessionLocal:
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session=Depends(get_db)) -> UserResponse:
    """ Register a new user"""
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail = "Username already registered")

    hashed_password = hash_password(user.password)
    db_user = User(
        username=user.username,
        password_hash= hashed_password,
        role=user.role

    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect password or username")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role.value},
        expires_delta = access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}



@app.get("/users", response_model=List[UserResponse])
def get_users(db: Session=Depends(get_db)) -> List[UserResponse]:
    """Get all users"""
    users = db.query(User).all()
    return users




