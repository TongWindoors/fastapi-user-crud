from typing import List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

app = FastAPI(title="User CRUD API", version="1.0.0")


# ---------- 数据模型 ----------

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


# ---------- “内存数据库” ----------
# 实际上就是一个 list，在程序运行期间存在，重启就没了

users_db: List[User] = []
next_user_id = 1  # 自增 id


def get_next_user_id() -> int:
    global next_user_id
    _id = next_user_id
    next_user_id += 1
    return _id


def find_user_index(user_id: int) -> int:
    for idx, user in enumerate(users_db):
        if user.id == user_id:
            return idx
    return -1


# ---------- 路由 ----------

@app.get("/users", response_model=List[User])
def list_users() -> List[User]:
    """获取所有用户列表"""
    return users_db


@app.get("/users/{user_id}", response_model=User)
def get_user(user_id: int) -> User:
    """根据 ID 获取单个用户"""
    idx = find_user_index(user_id)
    if idx == -1:
        raise HTTPException(status_code=404, detail="User not found")
    return users_db[idx]


@app.post("/users", response_model=User, status_code=201)
def create_user(user_in: UserCreate) -> User:
    """创建新用户"""
    # 简单示例：检查 email 是否已存在
    for u in users_db:
        if u.email == user_in.email:
            raise HTTPException(status_code=400, detail="Email already exists")

    user = User(
        id=get_next_user_id(),
        username=user_in.username,
        email=user_in.email,
        full_name=user_in.full_name,
        is_active=user_in.is_active,
    )
    users_db.append(user)
    return user


@app.put("/users/{user_id}", response_model=User)
def update_user(user_id: int, user_in: UserUpdate) -> User:
    """更新用户信息（全量/部分更新都支持）"""
    idx = find_user_index(user_id)
    if idx == -1:
        raise HTTPException(status_code=404, detail="User not found")

    stored_user = users_db[idx]

    updated_data = stored_user.dict()
    # 只更新传入的字段
    for key, value in user_in.dict(exclude_unset=True).items():
        updated_data[key] = value

    updated_user = User(**updated_data)
    users_db[idx] = updated_user
    return updated_user


@app.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int) -> None:
    """删除用户"""
    idx = find_user_index(user_id)
    if idx == -1:
        raise HTTPException(status_code=404, detail="User not found")
    users_db.pop(idx)
    # 204 没有响应
    return None