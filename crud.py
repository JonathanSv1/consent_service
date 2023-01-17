from datetime import timedelta
from typing import Union
from connect_database import connect_db

from fastapi import FastAPI, Depends, HTTPException, status

from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from pydantic import BaseModel
from login import create_access_token, SECRET_KEY, ALGORITHM
from jose import JWTError, jwt
from passlib.context import CryptContext
from services import Object, Roles, UserAccount
from enum import Enum

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



#
def decode_access_token(token: str) -> dict:
    try:
        decoded_data = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        return decoded_data
    except jwt.exceptions.DecodeError:
        raise ValueError("Invalid token")

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    username = payload.get("username")
    if username is None:
        raise HTTPException(status_code=400, detail="Token invalid")
    return username

def current_user(token: str = Depends(oauth2_scheme)):
    session = connect_db()
    payload = decode_token(token)
    user = session.query(UserAccount).filter(UserAccount.username == payload["username"]).first()
    #roles = session.query(Roles).filter(Roles.role_id == user.role_id).first()
    if user is None:
        raise HTTPException(status_code=400, detail="Token invalid")
    else:
        return user.user_id

def check_data_owner(token: str = Depends(get_current_user)):
    session = connect_db()
    user = session.query(UserAccount).filter(UserAccount.username == token).first()
    if user.role_id != 2:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="this route only access by Data Owner!!"
        )
    else:
        return user

def check_user(token: str = Depends(get_current_user)):
    session = connect_db()
    users = session.query(UserAccount).filter(UserAccount.username == token).first()
    roles = session.query(Roles).filter(Roles.role_id == users.role_id).first()
    if users.role_id == 1:
        return {"username": users.username, "name": users.name, "role": roles.role_name}
    if users.role_id == 2:
        return {"username": users.username, "name": users.name, "role": roles.role_name}
    if users.role_id == 3:
        return {"username": users.username, "name": users.name, "role": roles.role_name}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="you are not authorized to access this route!!"
        )

