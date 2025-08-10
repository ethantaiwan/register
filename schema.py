# schemas.py
from pydantic import BaseModel, EmailStr,constr
from models import Base
from typing import List
from datetime import datetime

class AuthorizeUsersRequest(BaseModel):
    emails: List[EmailStr]
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
class AddAccountRequest(BaseModel):
    username: str
    password: str
    provider_id: int
class ResetPasswordRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=16)  # 可自行調整規則
# models.py
#class UserDB(Base):
#    __tablename__ = "main_accounts"
#    account_id = Column(Integer, primary_key=True, index=True)
#    email = Column(String(100), unique=True, index=True)
#    pwd = Column(String(128))  # hashed password
#    status = Column(SmallInteger, default=9)
#    create_at = Column(DateTime, default=datetime.utcnow)

class Token(BaseModel):
    access_token: str
    token_type: str
class ElapseSetting(BaseModel):
    username: str
    seconds: int

class GameTimeSettingRequest(BaseModel):
    provider_name: str
    game_name: str  # or "全部"
    elapse_settings: List[ElapseSetting]
    
class WagerItemInput(BaseModel):
    ball: str  # e.g. "0102030405"
class WagerInput(BaseModel):
    provider_name: str
    game_name: str
    account_username: str
    bet_amount: int
    items: List[WagerItemInput]




