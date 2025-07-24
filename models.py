from sqlalchemy import Column, Integer, String, SmallInteger, DateTime,Identity
from sqlalchemy import Column, Integer, String, DateTime
from database import Base
import datetime
#class UserDB(Base):
#    __tablename__ = "users"
#    email = Column(String, primary_key=True, index=True)
#    hashed_password = Column(String)

#class User(BaseModel):
#    email: EmailStr
#    password: str

#class Token(BaseModel):
#    access_token: str
#    token_type: str

class UserDB(Base):
    __tablename__ = "main_accounts"

    account_id = Column(Integer, Identity(start=1, cycle=False), primary_key=True)
   # account_id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), unique=True, index=True)
    pwd = Column(String(128))  # hashed password 寫進這欄位
    status = Column(SmallInteger, default=9)
    create_at = Column(DateTime, default=datetime.utcnow)