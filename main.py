from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr

from sqlalchemy import Column, Integer, String, Boolean, create_engine, select
from sqlalchemy.orm import declarative_base, sessionmaker, Session

app = FastAPI(title="User CRUD API (DB Version)", version="1.0.0")

# =========================
# 数据库配置
# =========================

DATABASE_URL = "mysql+pymysql://root:123456@localhost:3306/fastapi_db"

engine = create_engine(
    DATABASE_URL,
    echo=True,         # 调试时打印 SQL，习惯后可以改为 False
    future=True
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


# =========================
# SQLAlchemy 模型（映射到 users 表）
# =========================

class UserORM(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), nullable=False)
    email = Column(String(100), nullable=False, unique=True, index=True)
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)


# 如果表不存在则创建（只需要在应用启动时执行一次）
Base.metadata.create_all(bind=engine)


# =========================
# Pydantic 模型（和你之前一样）
# =========================

class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool = True


class UserCreate(UserBase):
    password: str  # 只是示例，真实项目不会明文存密码


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None


class User(UserBase):
    id: int

    class Config:
        orm_mode = True  # 允许从 ORM 对象读取数据


# =========================
# 依赖：获取数据库 Session
# =========================

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
# 路由（CRUD）—— 改成操作数据库
# =========================

@app.get("/users", response_model=List[User])
def list_users(db: Session = Depends(get_db)) -> List[User]:
    """获取所有用户列表（从数据库）"""
    stmt = select(UserORM)
    result = db.execute(stmt)
    users = result.scalars().all()
    return users


@app.get("/users/{user_id}", response_model=User)
def get_user(user_id: int, db: Session = Depends(get_db)) -> User:
    """根据 ID 获取单个用户"""
    user = db.get(UserORM, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.post("/users", response_model=User, status_code=201)
def create_user(user_in: UserCreate, db: Session = Depends(get_db)) -> User:
    """创建新用户（写入数据库）"""

    # 检查 email 是否已存在
    stmt = select(UserORM).where(UserORM.email == user_in.email)
    existing = db.execute(stmt).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")

    user = UserORM(
        username=user_in.username,
        email=user_in.email,
        full_name=user_in.full_name,
        is_active=user_in.is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)  # 刷新以拿到自增 id

    return user


@app.put("/users/{user_id}", response_model=User)
def update_user(
    user_id: int,
    user_in: UserUpdate,
    db: Session = Depends(get_db)
) -> User:
    """更新用户信息（全量/部分更新都支持）"""

    user = db.get(UserORM, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = user_in.dict(exclude_unset=True)

    for field, value in update_data.items():
        setattr(user, field, value)

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(get_db)) -> None:
    """删除用户（从数据库删除）"""

    user = db.get(UserORM, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return None