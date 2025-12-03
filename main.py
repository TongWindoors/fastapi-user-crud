from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr

from sqlalchemy import Column, Integer, String, Boolean, create_engine, select
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from jose import JWTError, jwt
from passlib.context import CryptContext

from fastapi.middleware.cors import CORSMiddleware


# =========================
# 基本配置
# =========================

app = FastAPI(title="User API with JWT (POST only)", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # 开发环境直接全放行，后面可以收紧
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "change_this_to_a_random_long_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # token 有效期 60 分钟

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# OAuth2 使用的 token 提取方式（从 Authorization: Bearer xxx 里拿 token）
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# =========================
# 数据库配置
# =========================

DATABASE_URL = "mysql+pymysql://root:123456@localhost:3306/fastapi_db"

engine = create_engine(
    DATABASE_URL,
    echo=True,       # 调试时打印 SQL；稳定后可以改成 False
    future=True
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


class UserORM(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), nullable=False)
    email = Column(String(100), nullable=False, unique=True, index=True)
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    password_hash = Column(String(255), nullable=False, default="")


Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
# Pydantic 模型
# =========================

class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool = True


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    # 简化：这里先不支持改密码，有需要后面再加


class User(BaseModel):
    id: int
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


# =========================
# 密码 & JWT 工具函数
# =========================

def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_username(db: Session, username: str) -> Optional[UserORM]:
    stmt = select(UserORM).where(UserORM.username == username)
    return db.execute(stmt).scalar_one_or_none()


def authenticate_user(db: Session, username: str, password: str) -> Optional[UserORM]:
    user = get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> UserORM:
    """
    从 Authorization Header 里的 JWT token 中解析当前用户
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = get_user_by_username(db, token_data.username)
    if user is None:
        raise credentials_exception
    return user


# =========================
# Auth 接口：注册 + 登录（都是 POST）
# =========================

@app.post("/auth/register", response_model=User, status_code=201)
def register(user_in: UserCreate, db: Session = Depends(get_db)) -> User:
    # 检查 username / email 是否已存在
    existing_user = db.execute(
        select(UserORM).where(UserORM.username == user_in.username)
    ).scalar_one_or_none()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    existing_email = db.execute(
        select(UserORM).where(UserORM.email == user_in.email)
    ).scalar_one_or_none()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already exists")

    user = UserORM(
        username=user_in.username,
        email=user_in.email,
        full_name=user_in.full_name,
        is_active=user_in.is_active,
        password_hash=get_password_hash(user_in.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    登录接口：
    - 请求体用 x-www-form-urlencoded
    - 字段：username, password
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")


# =========================
# 用户相关接口（全部使用 POST）
# =========================

@app.post("/users/list", response_model=List[User])
def list_users(db: Session = Depends(get_db)) -> List[User]:
    """
    获取所有用户列表（POST 方式）
    真实项目中一般只允许 admin 使用，这里用于调试和自测。
    """
    stmt = select(UserORM)
    users = db.execute(stmt).scalars().all()
    return users


@app.post("/users/me/get", response_model=User)
async def read_current_user(
    current_user: UserORM = Depends(get_current_user),
) -> User:
    """
    获取当前登录用户信息（POST 方式）
    取代原来的 GET /users/me 或 GET /users/{user_id}
    """
    return current_user


@app.post("/users/me/update", response_model=User)
async def update_current_user(
    user_in: UserUpdate,
    db: Session = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> User:
    """
    更新当前登录用户信息（POST 方式）
    不再使用 PUT /users/me
    """
    update_data = user_in.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(current_user, field, value)

    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return current_user


@app.post("/users/me/delete", status_code=204)
async def delete_current_user(
    db: Session = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> None:
    """
    删除当前登录用户账号（POST 方式）
    取代 DELETE /users/me
    """
    db.delete(current_user)
    db.commit()
    return None