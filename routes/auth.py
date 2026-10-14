from core.security import create_access_token, get_current_user, create_refresh_token, hash_refresh_token
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from database import get_session
from pwdlib import PasswordHash
from models.user import User
from models.refresh_token import RefreshToken
from schemas.auth import SignupRequest, LoginRequest, RefreshRequest
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone

router = APIRouter(prefix="/auth", tags=['Auth'])
password_hash = PasswordHash.recommended()

@router.post('/login')
def login(data: LoginRequest, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == data.username)).first()
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password!"
        )
    verify = password_hash.verify(data.password, user.password)
    if not verify:
        raise HTTPException(status_code=401,detail="Invalid username or password!")
    refresh_token = create_refresh_token()
    token_record = RefreshToken(user_id=user.id, token_hash=hash_refresh_token(refresh_token), expires_at=datetime.now(timezone.utc) + timedelta(days=7))
    session.add(token_record)
    session.commit()
    token  = create_access_token(user.id)
    return {"user":{"id":user.id, "username": user.username},  "access_token":token, "token_type":"bearer", "refresh_token":refresh_token}    

@router.post('/signup')
def signup(data: SignupRequest, session: Session = Depends(get_session)):
    user = User(username=data.username, password = password_hash.hash(data.password))
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Username already exists!")
    session.refresh(user)
    return {"id":user.id, "username":user.username}


@router.get('/me')
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id":current_user.id,
        "username":current_user.username
    }
    
@router.post("/refresh")
def refresh(data: RefreshRequest, session: Session = Depends(get_session)):
    token_hash = hash_refresh_token(data.refresh_token)
    
    record = session.exec(select(RefreshToken).where(RefreshToken.token_hash == token_hash)).first()
    if record is None or record.revoked or record.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )
    record.revoked = True
    session.add(record)
    session.commit()
    
    new_refresh_token = create_access_token()
    new_record = RefreshToken(user_id=record.user_id, token_hash=hash_refresh_token(new_refresh_token), expires_at=datetime.now(timezone.utc) + timedelta(days=7))
    
    session.add(new_record)
    session.commit()
    access_token = create_access_token(record.user_id)
    
    
    return {
        "refresh_token":new_refresh_token,
        "access_token":access_token,
        "token_type":"bearer"
    }
    
    
@router.post("/logout")
def logout(data: RefreshRequest, session:Session = Depends(get_session)):
    token_hash = hash_refresh_token(data.refresh_token)
    
    record = session.exec(select(RefreshToken).where(token_hash=token_hash)).first()
    
    if record and not record.revoked:
        record.revoked = True
        session.add(record)
        session.commit()
    
    return {"message":"Logout success!"}