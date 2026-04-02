from fastapi import FastAPI, HTTPException, Depends
from httpx import put
import uvicorn
from models import UserRegister, UserLogin, UserRefresh
from database import sqlite3, create_database
from utils import hash_password, verify_password
from jwt_handler import create_access_token, create_refresh_token, decode_token
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, ExpiredSignatureError
from typing import Optional


app = FastAPI()
create_database()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Endpoints for users to register, login, refresh token
@app.post("/register")
def register(data: UserRegister):
    with sqlite3.connect("ecommerce.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (data.email,))
        existing_user = cursor.fetchone()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        cursor.execute("INSERT INTO users (name, email, password, role) VALUES (?,?,?,?)",
                   (data.name, data.email, hash_password(data.password), "user")
        )
        conn.commit()

        return {"message": "User registered successfully"} 

@app.post("/login")
def login(User: UserLogin):
    with sqlite3.connect("ecommerce.db") as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? ", (User.email,))

        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=403, detail="Invalid Email")
        print(f"DEBUG: user tuple = {user}, length = {len(user)}")
        is_valid = verify_password(User.password, user["password"])

        if not is_valid:
            raise HTTPException(status_code=403, detail="Invalid password")
        
        access_token = create_access_token({
            "sub": user["email"],
            "name": user["name"],
            "role": user["role"]
        })

        refresh_token = create_refresh_token({
            "sub": user["email"],
            "name": user["name"],
            "role": user["role"]
        })
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    
@app.post("/refresh")
def refresh(Refresh: UserRefresh):
    
    try:
        payload = decode_token(Refresh.token)
        token_type = payload["token_type"]
    
        if token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token")
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    with sqlite3.connect("ecommerce.db") as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (payload["sub"],))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        access_token = create_access_token({
            "sub": user["email"],
            "name": user["name"],
            "role": user["role"]
        })

        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
