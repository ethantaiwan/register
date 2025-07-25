import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer

from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import os

from models import UserDB, GameAccountDB
from schema import UserCreate, LoginRequest, Token, AuthorizeUsersRequest, AddAccountRequest
from database import SessionLocal, Base
from passlib.context import CryptContext
from auth import get_password_hash
from cryptography.fernet import Fernet
#from dotenv import load_dotenv
import os


# ======== 加密與JWT設定 ==========
#SECRET_KEY = "6fbb6277a271e0f2a5b932d68376bbb0af3590da77f1a81b9fa9fcb64edf41fb"
SECRET_KEY = os.environ.get("token")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in environment variables")
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set in environment variables")
keys = Fernet(os.environ.get("key"))
if not keys:
    raise RuntimeError("key is not set in environment variables")
fernet = Fernet(keys)
#SECRET_KEY =os.env['token']
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# 建立 DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
def hash_password(password: str):
    return pwd_context.hash(password)
def encrypt_pwd(pwd: str) -> str:
    return fernet.encrypt(pwd.encode()).decode()
def decrypt_pwd(enc_pwd: str) -> str:
    return fernet.decrypt(enc_pwd.encode()).decode()    
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

#engine = create_engine(DATABASE_URL)
#SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
@app.get("/")
def read_root():
    return {"msg": "FastAPI is running"}

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
#@app.post("/login", response_model=Token)
@app.post("/login")
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.email == login_data.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Email不正確")
    if user.status != 0:
        raise HTTPException(status_code=403, detail="請等待管理者授權")
    if not pwd_context.verify(login_data.password, user.pwd):
        raise HTTPException(status_code=400, detail="密碼不正確")
    return {"message": "登入成功", "user_id": user.email.split("@")[0]}
    #access_token = create_access_token(data={"sub": user.email})
    #return {"登入成功：access_token": access_token, "token_type": "bearer"}
@app.post("/authorize-users")
def authorize_users(request: AuthorizeUsersRequest, db: Session = Depends(get_db)):
    updated_count = (
        db.query(UserDB)
        .filter(UserDB.email.in_(request.emails), UserDB.status == 9)
        .update({UserDB.status: 0}, synchronize_session=False)
    )
    if not updated_count:
        raise HTTPException(status_code=404, detail="沒有找到可授權的使用者帳號")
    db.commit()
    return {"msg": f"{updated_count} user(s) authorized"}
@app.post("/add-gameaccount")
def add_account(gamedata: AddAccountRequest, db: Session = Depends(get_db)):
    # 檢查帳號是否已存在
    existing = db.query(GameAccountDB).filter_by(username=gamedata.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="此帳號已存在")
    encrypt_password = encrypt_pwd(gamedata.password)
    new_account = GameAccountDB(
        username=gamedata.username,
        pwd=encrypt_password,
        provider_id=gamedata.provider_id
    )
    db.add(new_account)
    db.commit()
    db.refresh(new_account)
    return {"msg": "帳號新增成功！", "account": new_account.username}
@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    return {"msg": "You're authenticated!"}
    import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)

