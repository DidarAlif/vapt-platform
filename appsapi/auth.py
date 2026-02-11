import os
import bcrypt
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from database import get_db
from models import User
from email_service import generate_verification_token, send_verification_email, is_token_expired

# Security configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Bearer token scheme
security = HTTPBearer(auto_error=False)


# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    is_verified: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenData(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


# Password utilities - using bcrypt directly
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash."""
    password_bytes = plain_password.encode('utf-8')
    hash_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hash_bytes)


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


# Token utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str, expected_type: str = "access") -> Optional[TokenData]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != expected_type:
            return None
        user_id: str = payload.get("sub")
        email: str = payload.get("email")
        if user_id is None:
            return None
        return TokenData(user_id=user_id, email=email)
    except JWTError:
        return None


# User utilities
def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def get_user_by_verification_token(db: Session, token: str) -> Optional[User]:
    return db.query(User).filter(User.verification_token == token).first()


def create_user(db: Session, user_data: UserCreate) -> User:
    """Create a new user. Email verification is currently bypassed — users are auto-verified."""
    hashed_password = get_password_hash(user_data.password)
    
    # Bypass email verification: auto-verify all new users
    db_user = User(
        email=user_data.email,
        password_hash=hashed_password,
        name=user_data.name,
        is_verified=True,  # Auto-verified (email verification bypassed)
        verification_token=None,
        verification_sent_at=None
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    print(f"[Auth] Email verification bypassed - user {user_data.email} auto-verified")
    return db_user


def verify_user_email(db: Session, token: str) -> Optional[User]:
    """Verify user email with token."""
    user = get_user_by_verification_token(db, token)
    if not user:
        return None
    
    # Check if token expired
    if is_token_expired(user.verification_sent_at):
        return None
    
    user.is_verified = True
    user.verification_token = None
    db.commit()
    db.refresh(user)
    return user


def resend_verification_email(db: Session, email: str) -> bool:
    """Resend verification email to unverified user."""
    user = get_user_by_email(db, email)
    if not user or user.is_verified:
        return False
    
    # Generate new token
    new_token = generate_verification_token()
    user.verification_token = new_token
    user.verification_sent_at = datetime.utcnow()
    db.commit()
    
    # Send email
    return send_verification_email(user.email, user.name, new_token)


def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.password_hash):
        return None
    return user


# Dependency for protected routes
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    if not credentials:
        return None
    
    token_data = verify_token(credentials.credentials)
    if not token_data:
        return None
    
    user = db.query(User).filter(User.id == token_data.user_id).first()
    return user


async def require_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token_data = verify_token(credentials.credentials)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = db.query(User).filter(User.id == token_data.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    
    return user


async def require_verified_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Require authenticated user. Email verification is currently bypassed."""
    # Email verification bypassed — just require authentication
    return await require_user(credentials, db)


async def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user
