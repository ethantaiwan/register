# schemas.py
from pydantic import BaseModel, EmailStr
from models import Base

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

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
