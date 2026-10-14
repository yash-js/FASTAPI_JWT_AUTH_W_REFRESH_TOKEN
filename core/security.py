import os, jwt, secrets, hashlib
from datetime import datetime, timezone, timedelta
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from jwt.exceptions import InvalidTokenError
from fastapi import Depends, HTTPException
from database import Session, get_session
from sqlmodel import select
from models.user import User

http_scheme = HTTPBearer()

def create_access_token(user_id:int):
    payload = {
        "sub": str(user_id),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "algorithms":["HS256"]
    }
    token = jwt.encode(payload,os.getenv("JWT_SECRET"))
    return token


def verify_access_token(token:str):
    try:
        return jwt.decode(token, os.getenv("JWT_SECRET"),algorithms=["HS256"])
    except InvalidTokenError:
        return None

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(http_scheme), session:Session = Depends(get_session)):
    token = credentials.credentials
    payload = verify_access_token(token)

    if payload is None:
        raise HTTPException(status_code=401, detail="Unauthorized request!")
    
    user_id = payload.get('sub')
    if user_id is None:
        raise HTTPException(status_code=401, detail="Unauthorized request!")
        
    user = session.exec(select(User).where(User.id == int(user_id))).first()
    
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized request!")
    
    return user


def create_refresh_token():
    return secrets.token_urlsafe(32)

def hash_refresh_token(token:str):
    # .encode() converts it to bytes, sha256 calculates bytes of hash, hexdigest() converts to readalbe hexadecimal
    return hashlib.sha256(token.encode()).hexdigest()


