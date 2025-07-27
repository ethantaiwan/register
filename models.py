from sqlalchemy import Column, Integer, String, SmallInteger, DateTime, Identity
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime

from database import Base
from datetime import datetime
from sqlalchemy import ForeignKey

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
class GameAccountDB(Base):
    __tablename__ = "accounts"
    account_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(100), nullable=False)
    pwd = Column(String(128), nullable=False)
    #provider_id = Column(Integer, nullable=False)  # 可依需求設 ForeignKey
    provider_id = Column(Integer, ForeignKey("providers.provider_id"))
class Provider(Base):
    __tablename__ = "providers"
    provider_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(8) )
class GameUserMappingDB(Base):
    __tablename__ = "games"
    game_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    account_id = Column(Integer, ForeignKey("accounts.account_id"))
    provider_id = Column(Integer, ForeignKey("providers.provider_id"))
    game_name = Column(String(8))  # 視你 DB schema 決定長度
    game_elapse = Column(SmallInteger)  
    flag = Column(Boolean, default=False)

# models.py
class Wager(Base):
    __tablename__ = "wager"
    w_id = Column(Integer, primary_key=True,index=True, autoincrement=True)
    w_date_time = Column(DateTime)
    bet_type = Column(String(50))
    p_id = Column(SmallInteger,ForeignKey("providers.provider_id"))
    game_id = Column(SmallInteger,ForeignKey("games.game_id"))
    account_id = Column(SmallInteger,ForeignKey("accounts.account_id"))
    bet_flag = Column(Boolean)


class WagerItem(Base):
    __tablename__ = "wager_item"
    w_id = Column(Integer,ForeignKey("wager.w_id"))
    wager_item_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    e_date_time = Column(DateTime)
    ball = Column(String(64))
    status = Column(SmallInteger)
    win_loss = Column(SmallInteger)
    bet_amount = Column(Integer)
    win_amount = Column(Integer)
    deduct_amount = Column(Integer)


