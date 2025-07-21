from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

from ..database import get_db
from ..models import User
from ..schemas import UserCreate, UserLogin, UserResponse

SECRET_KEY = "your_secret_key_here"  # 실제 배포시 환경변수로 관리
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()

# 비밀번호 해시/검증

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# JWT 토큰 생성/검증

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# 회원가입
@router.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == user.username) | (User.email == user.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already registered")
    hashed_pw = get_password_hash(user.password)
    db_user = User(username=user.username, email=user.email, password_hash=hashed_pw)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# 로그인
@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token({"sub": str(db_user.id), "role": db_user.role})
    return {"access_token": access_token, "token_type": "bearer", "user": UserResponse.model_validate(db_user)}

# 현재 유저 가져오기 (토큰 기반)
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# 권한(Role) 체크 의존성

def require_role(role: str):
    def role_checker(user: User = Depends(get_current_user)):
        if user.role != role:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return role_checker

# 예시: 관리자만 접근 가능한 엔드포인트
@router.get("/admin-only")
def admin_only(user: User = Depends(require_role("admin"))):
    return {"message": f"Hello, admin {user.username}"} 