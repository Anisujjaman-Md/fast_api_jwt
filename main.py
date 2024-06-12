# main.py
from fastapi import FastAPI, HTTPException
import databases
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta

app = FastAPI()
# Database configuration
DATABASE_URL = "postgresql://postgres:2203@localhost/f"
database = databases.Database(DATABASE_URL)
metadata = MetaData()

# Table definition
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(50), unique=True),
    Column("password", String(100)),
    Column("email", String(100), unique=True),
)

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()



# Define JWT settings
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Define OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Authenticate user
def authenticate_user(username: str, password: str):
    # Replace this with your actual authentication logic
    if username == "user" and password == "password":
        return True
    return False

# Create access token
def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"exp": expire, **data}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Token endpoint
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(form_data.username, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class User(BaseModel):
    username: str
    password: str
    email:str

@app.post("/register")
async def register_user(user: User):
    try:
        password = pwd_context.hash(user.password)
        query = users.insert().values(username=user.username, password=password, email = user.email)
        await database.execute(query)
        access_token = create_access_token(data={"username": user.username})
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        return {"massage": str(e)}
    
@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("username")
    return {"username": payload}


engine = create_engine(DATABASE_URL)
metadata.create_all(engine)