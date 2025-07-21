from fastapi import FastAPI, HTTPException, Depends, status, Path
from sqlalchemy.orm import Session
from typing import List

from models import User, UserRole, PsychicProfile
from shemas import UserCreate, UserResponse, Token, PsychicProfileCreate, PsychicProfileResponse
from auth import hash_password, verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM
from database import SessionLocal, engine
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import timedelta
from jose import jwt, JWTError


app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db() -> SessionLocal:
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db))->User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},

    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user





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

@app.post("/psychics", response_model=PsychicProfileResponse)
def create_psychic_profile(
        profile: PsychicProfileCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Only admins can create psychic profiles")
    db_profile = PsychicProfile(**profile.dict())
    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)
    return db_profile



@app.get("/users", response_model=List[UserResponse])
def get_users(current_user: User = Depends(get_current_user), db: Session=Depends(get_db)) -> List[UserResponse]:
    """Get all users"""
    return db.query(User).all()

@app.get("/psychics", response_model=List[PsychicProfileResponse])
def get_psychics(db: Session = Depends(get_db)):
    return db.query(PsychicProfile).all()

@app.get("/psychics/{psychic_id}", response_model=PsychicProfileResponse)
def get_psychic(psychic_id: int, db: Session = Depends(get_db)):
    profile = db.query(PsychicProfile).filter(PsychicProfile.id == psychic_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Psychic profile not found")
    return profile

@app.put("/psychics/{psychic_id}", response_model=PsychicProfileResponse)
def update_psychic_profile(
        psychic_id: int,
        profile: PsychicProfileCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail = "Only admins can update psychic profiles")
    db_profile = db.query(PsychicProfile).filter(PsychicProfile.id == psychic_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail = "Psychic profile not found")
    db_profile.name = profile.name
    db_profile.description = profile.description
    db_profile.avatar_url = profile.avatar_url
    db.commit()
    db.refresh(db_profile)
    return db_profile

@app.delete("/psychics/{psychic_id}")
def delete_psychic(
        psychic_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail = "Only admins can delete psychic profiles")
    db_profile = db.query(PsychicProfile).filter(PsychicProfile.id == psychic_id).first()
    if not db_profile:
        raise HTTPException(status_code=404, detail = "Psychic profile not found")
    db.delete(db_profile)
    db.commit()
    return {"detail": "Psychic profile deleted"}






