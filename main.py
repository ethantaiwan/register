import uvicorn
from fastapi import FastAPI, HTTPException, Depends, APIRouter, Query
from fastapi.security import OAuth2PasswordBearer

from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import os

from models import UserDB, GameAccountDB, GameUserMappingDB, Provider, Wager, WagerItem
from schema import UserCreate, LoginRequest, Token, AuthorizeUsersRequest, AddAccountRequest, GameTimeSettingRequest, WagerInput, WagerItemInput
from database import SessionLocal, Base
from passlib.context import CryptContext
from auth import get_password_hash
from cryptography.fernet import Fernet
from fastapi.middleware.cors import CORSMiddleware

# ======== 加密與JWT設定 ==========

from fastapi.middleware.cors import CORSMiddleware


#SECRET_KEY = "6fbb6277a271e0f2a5b932d68376bbb0af3590da77f1a81b9fa9fcb64edf41fb"
SECRET_KEY = os.environ.get("token")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in environment variables")
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set in environment variables")
keys = os.environ.get("key")
#keys = b'6a2xU1iwZfoVs5n9vXeZsEZ5etySe6XSx0Jvd2uEh5k='
if not keys:
    raise RuntimeError("key is not set in environment variables")
fernet = Fernet(keys)
#SECRET_KEY =os.env['token']
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://victory-umey.onrender.com","http://localhost:8080"],  # 或指定你的前端網址
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
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
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception
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
#router = APIRouter() #router 使用

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
    access_token = create_access_token(data={"sub": user.email})
    return {
    "access_token": access_token,
    "token_type": "bearer",
    "user_id": user.email.split("@")[0]
    }
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

@app.post("/update-mapping-flags")
def update_mapping_flags(data: dict, db: Session = Depends(get_db)):
    """
    data 例子：
    {
        "provider": "IBM",
        "mappings": [
            {
                "username": "Ace",
                "games": ["539", "天天樂"]
            },
            {
                "username": "King",
                "games": ["六合"]
            }
        ]
    }
    """
    #router = APIRouter()
    provider_name = data.get("provider")
    mappings = data.get("mappings", [])

    # 取得 provider_id
    provider = db.query(Provider).filter_by(name=provider_name).first()
    if not provider:
        raise HTTPException(status_code=400, detail="該平台不存在")

    provider_id = provider.provider_id

    for item in mappings:
        username = item["username"]
        selected_games = item["games"]

        # 查詢帳號
        account = db.query(GameAccountDB).filter_by(username=username,provider_id=provider.provider_id).first()
        if not account:
            raise HTTPException(status_code=400, detail=f"帳號 {username} 不存在於 provider {provider.name}")

        # 查詢該帳號在該平台的所有遊戲紀錄
        all_rows = db.query(GameUserMappingDB).filter_by(
            account_id=account.account_id,
            provider_id=provider_id
        ).all()

        for row in all_rows:
            row.flag = row.game_name in selected_games


    db.commit()
    return {"msg": "flag 更新完成"}

@app.post("/set-game-elapse")
def set_game_elapse(data: GameTimeSettingRequest, db: Session = Depends(get_db)):
    provider = db.query(Provider).filter_by(name=data.provider_name).first()
    if not provider:
        raise HTTPException(status_code=404, detail="平台不存在")

    for setting in data.elapse_settings:
        account = db.query(GameAccountDB).filter_by(username=setting.username, provider_id=provider.provider_id).first()
        if not account:
            raise HTTPException(status_code=400, detail=f"帳號 {username} 不存在於 provider {provider.name}")

        query = db.query(GameUserMappingDB).filter_by(account_id=account.account_id, provider_id=provider.provider_id)

        if data.game_name != "全":
            query = query.filter_by(game_name=data.game_name)

        records = query.all()
        for record in records:
            record.game_elapse = setting.seconds

    db.commit()
    return {"message": "更新成功"}
from datetime import datetime

@app.post("/submit-wager")
def submit_wager(payload: WagerInput, db: Session = Depends(get_db)):
    provider = db.query(Provider).filter_by(name=payload.provider_name).first()
    if not provider:
        raise HTTPException(status_code=404, detail="遊戲平台錯誤")

    account = db.query(GameAccountDB).filter_by(username=payload.account_username, provider_id=provider.provider_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="找不到該帳號")

    mapping = db.query(GameUserMappingDB).filter_by(account_id=account.account_id, provider_id=provider.provider_id, game_name=payload.game_name).first()
    if not mapping:
        raise HTTPException(status_code=404, detail="遊戲名稱不正確")

    now = datetime.now()

    new_wager = Wager(
        w_date_time=now,
        bet_type="234",
        p_id=provider.provider_id,
        game_id=mapping.game_id,
        account_id=account.account_id,
        bet_flag=False,
    )
    db.add(new_wager)
    db.flush()  # 拿 w_id

    for item in payload.items:
        wager_item = WagerItem(
            w_id=new_wager.w_id,
            e_date_time=now,
            ball=item.ball,
            status=999,
            bet_amount=payload.bet_amount,
            win_loss=None,
            win_amount=None,
            deduct_amount=None,
        )
        db.add(wager_item)

    db.commit()
    return {"status": "success", "wager_id": new_wager.w_id}

@app.get("/get-usernames")
def get_usernames(provider_id: int = Query(...),game_name: str = Query(...),db: Session = Depends(get_db)):
    game = db.query(GameUserMappingDB).filter(
        GameUserMappingDB.provider_id == provider_id,
        GameUserMappingDB.game_name == game_name
    ).first()

    if not game:
        raise HTTPException(status_code=404, detail="Game not found")

    usernames = db.query(GameAccountDB.username).filter(GameAccountDB.provider_id == game.provider_id).all()

    return {"usernames": [u.username for u in usernames]}

@app.get("/get-username-time")
def get_username_time(provider_id: int, game_name: str, db: Session = Depends(get_db)):
    results = db.query(
        GameAccountDB.username,
        GameUserMappingDB.game_elapse
    ).join(
        GameUserMappingDB,
        GameUserMappingDB.account_id == GameAccountDB.account_id
    ).filter(
        GameUserMappingDB.provider_id == provider_id,
        GameUserMappingDB.game_name == game_name
    ).all()

    return [
        {"username": username, "seconds": elapse}
        for username, elapse in results
    ]
@app.get("/get-password")
def get_password(provider_id: int,username:str,db: Session = Depends(get_db)):
    
@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    return {"msg": "You're authenticated!"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)

# 自動參數 帳號,加密密碼,平台,遊戲,球號,bet_type,金額
    #,判斷哪個平台 呼叫不同的code 判斷 哪個遊戲 球數會不同, 密碼要在執行時才解開
