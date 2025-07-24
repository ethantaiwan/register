from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from auth import hash_password, verify_password, create_access_token
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import Base, UserDB
from schema import UserCreate, LoginRequest, Token
from auth import get_password_hash, verify_password
import os
#app = FastAPI()
#oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

import sys
#sys.path.append('/content/drive/MyDrive/bet/')  # 或你實際的目錄
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
# ======== 模擬用戶資料庫 ==========
fake_users_db = {}

# ======== 加密與JWT設定 ==========
#SECRET_KEY = "6fbb6277a271e0f2a5b932d68376bbb0af3590da77f1a81b9fa9fcb64edf41fb"
SECRET_KEY = os.environ.get("token")

#SECRET_KEY =os.env['token']
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# 建立 DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ======== 資料模型 ==========
class User(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# ======== FastAPI app ==========
# 用你的 DATABASE_URL 建立連線
#DATABASE_URL = "postgresql://main_z378_user:nSpZ4S5IlPt16a4bb7oZCeOZsoaOaAcM@dpg-d207mb6mcj7s73aqsvg0-a.singapore-postgres.render.com:5432/main_z378"
DATABASE_URL = DATABASE_URL = os.environ.get("DATABASE_URL")
#engine = create_engine(DATABASE_URL)
#SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    new_user = UserDB(email=user.email, pwd=hashed_password, status=9)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "Registered successfully"}

@app.post("/login", response_model=Token)

def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.email == login_data.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Email not found")
    if not pwd_context.verify(login_data.password, user.pwd):
        raise HTTPException(status_code=400, detail="Incorrect password")
    return {"message": "Login successful", "user_id": user.account_id}

@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    return {"msg": "You're authenticated!"}

