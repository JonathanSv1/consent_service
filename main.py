from datetime import datetime, timedelta
from typing import Union
from connect_database import connect_db

from fastapi import FastAPI, Depends, HTTPException, status

from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from pydantic import BaseModel
from login import create_access_token, SECRET_KEY, ALGORITHM
from jose import JWTError, jwt
from passlib.context import CryptContext
from services import Consent_dataset, Consent_request, Object, Roles, UserAccount
from enum import Enum
from crud import  check_user, current_user, check_data_owner, decode_token, get_current_user




session = connect_db()

#
class Role(int, Enum):
    end_user = "1"
    data_owner = "2"
    data_consumer = "3"

class Consent_method(str, Enum):
    always = "always"
    user = "user"
    per_req = "per_request"

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None

class User(BaseModel):
    username: str
    name: str
    role_id: int

class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


#List object : TABLE object
@app.get("/list_object", tags=["Data Owner"])
def get_object():
    session = connect_db()
    objects = session.query(Object).all()
    object_list = []
    for obj in objects:
        object_list.append({"object_id": obj.object_id, "object_name": obj.object_name, "show": obj.show, "process": obj.process, "forward": obj.forward, "expire": obj.expire})
    session.close()
    return object_list

#Insert object : TABLE object
@app.post("/insert_object/", tags=["Data Owner"],dependencies=[Depends(check_data_owner)])
def insert_object(object_name: str, show: bool, process: bool, forward: bool, expire: int, consent_method: Consent_method, owner_id: int = Depends(current_user)):
    session = connect_db()
    new_object = Object(object_name=object_name, owner_id = owner_id, show=show, process=process, forward=forward, expire=expire, consent_method=consent_method)
    session.add(new_object)
    session.commit()
    session.close()
    return {"Object insert success!!"}

#Delete object : TABLE object
@app.delete("/delete/{object_id}", tags=["Data Owner"], dependencies=[Depends(check_data_owner)])
def delete_object(object_id: int, user_id: int = Depends(current_user)):
    session = connect_db()
    obj = session.query(Object).filter(Object.object_id == object_id).first()
    if obj and obj.owner_id == user_id:
        session.delete(obj)
        session.commit()
        return {"Object deleted success!!"}
    elif obj and obj.owner_id != user_id:
        session.close()
        raise HTTPException(status_code=400, detail="You are not authorized to delete this object")
    else:
        session.close()
        raise HTTPException(status_code=400, detail="Object not found")


#Update object : TABlE object
@app.put("/update/{object_id}", tags=["Data Owner"], dependencies=[Depends(check_data_owner)])
def update_object(object_id: int, object_name: str, show: bool, process: bool, forward: bool):
    session = connect_db()
    obj = session.query(Object).filter(Object.object_id == object_id).first()
    if obj:
        obj.object_name = object_name
        obj.show = show
        obj.process = process
        obj.forward = forward
        session.commit()
        return {"Object updated success!!"}
    else:
        session.close()
        return {"error": "Object not found"}

#register : TABLE user_account
@app.post("/register", tags=["Users"])
def register(username: str, password: str, name: str , role_id: int):
    session = connect_db()
    existing_user = session.query(UserAccount).filter(UserAccount.username == username).first()
    if existing_user:
        return {"message": "username already exists"}
    else:
        hashed_password = pwd_context.hash(password)
        new_user = UserAccount(username=username, password=hashed_password, name=name, role_id=role_id)
        session.add(new_user)
        session.commit()
        return {"username": username, "name": name, "role": role_id}


# Login : TABLE user_account
@app.post("/token", tags=["Users"], response_model=Token)
async def login_for_access_token(from_data: OAuth2PasswordRequestForm = Depends()):
    session = connect_db()
    user = session.query(UserAccount).filter(UserAccount.username == from_data.username).first()
    if user and pwd_context.verify(from_data.password, user.password):
        access_token = create_access_token(
            data={"username": user.username, "role": user.role_id}
        )
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Check current user
@app.get("/users/me", tags=["Check Users"])
async def read_users_me(current_user: str = Depends(check_user)):
    return {"current user is": current_user}


# list object type "user"
@app.get("/list_object/consent_method/user", tags=["Consent Dataset"])
def list_objects():
    session = connect_db()
    objects_user = session.query(Object).filter(Object.consent_method == "user").all()
    return objects_user


# Consent dataset
@app.post("/consent_dataset", tags=["Consent Dataset"])
def consent_dataset(object_id: int, user_id: int = Depends(current_user)):
    session = connect_db()
    cs_date = datetime.now()
    obj = session.query(Object).filter(Object.object_id == object_id).first()
    if obj is None:
        raise HTTPException(status_code=404, detail="Object not found")
    if obj.consent_method != "user":
        raise HTTPException(status_code=404, detail="Invalid consent method")
    existing_consent = session.query(Consent_dataset).filter(Consent_dataset.object_id == object_id, Consent_dataset.user_id == user_id).first()
    if existing_consent:
        raise HTTPException(status_code=400, detail="Object has been consented")
    obj_expire = obj.expire
    obj_name = obj.object_name
    consent = Consent_dataset(consent_dataset_date = cs_date, user_id = user_id, object_id = object_id, expire=obj_expire)
    session.add(consent)
    session.commit()
    session.close()
    return {"object consented name": obj_name}


# revoke consent : update revoke_date
@app.put("/revoke/{consent_dataset_id}", tags=["Consent Dataset"])
def update_revoke_date(consent_dataset_id: int, user_id: int = Depends(current_user)):
    session = connect_db()
    consent = session.query(Consent_dataset).filter(Consent_dataset.consent_dataset_id == consent_dataset_id, Consent_dataset.user_id == user_id).first()
    if consent is None:
        raise HTTPException(status_code=404, detail="Object not found or not consented by user")
    consent.revoke_date = datetime.now()
    session.commit()
    session.close()
    return {"consent has been revoke"}


# list object type "per_request"
@app.get("/list_object/consent_method/per_req")
def list_objects():
    session = connect_db()
    objects_user = session.query(Object).filter(Object.consent_method == "per_request").all()
    return objects_user

# consent request
@app.post("/consent_request")
def consent_request(object_id: int, req_info: str):
    session = connect_db()
    req_date = datetime.now()
    obj = session.query(Object).filter(Object.object_id == object_id).first()
    if obj is None:
        raise HTTPException(status_code=404, detail="Object not found")
    if obj.consent_method != "per_request":
        raise HTTPException(status_code=404, detail="Invalid consent method")
    existing_request = session.query(Consent_request).filter(Consent_request.object_id == object_id).first()
    if existing_request:
        raise HTTPException(status_code=400, detail="A consent request has been sent for this object")
    cs_req = Consent_request(request_date = req_date, request_info = req_info, object_id = obj.object_id)
    session.add(cs_req)
    session.commit()
    session.close()
    return {"A consent request has been sent to the End_User"}

# consent response
@app.put("/consent_response/{request_id}")
def consent_response(request_id: int,response: bool):
    session = connect_db()
    req = session.query(Consent_request).filter(Consent_request.request_id == request_id).first()
    if req is None:
        raise HTTPException(status_code=404, detail="Request not found")
    req.response = response
    req.response_date = datetime.now()
    session.commit()
    session.close()
    return {"Consent request has been response"}

# list consent request
@app.get("/list_request")
def list_consent_request():
    session = connect_db()
    list_req = session.query(Consent_request).filter(Consent_request.response == None).all()
    if not list_req:
        raise HTTPException(status_code=404, detail="No consent request")
    return list_req

# จากตาราง consent_dataset 
@app.get("/check_coonsented")
def check_consented(object_id: int):
    session = connect_db()
    consented = session.query(Consent_dataset).filter(Consent_dataset.object_id == object_id).all()
    return consented
