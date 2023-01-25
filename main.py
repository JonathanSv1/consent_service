from datetime import date, datetime, timedelta
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
from crud import  check_data_consumer, check_end_user, current_user, check_data_owner, decode_token, get_current_user
from sqlalchemy.sql import and_




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
@app.get("/list_all_object", tags=["Data Consumer"])
def get_object():
    session = connect_db()
    objects = session.query(Object).all()
    object_list = []
    for obj in objects:
        object_list.append({"object_id": obj.object_id, "object_name": obj.object_name, "show": obj.show, "process": obj.process, "forward": obj.forward, "expire": obj.expire, "consent_method": obj.consent_method})
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
    if obj and obj.owner_id != user_id:
        session.close()
        raise HTTPException(status_code=400, detail="You are not authorized to delete this object")
    else:
        session.close()
        raise HTTPException(status_code=400, detail="Object not found")


#Update object : TABlE object
@app.put("/update/{object_id}", tags=["Data Owner"])
def update_object(object_id: int, object_name: str, show: bool, process: bool, forward: bool, expire: int, user_id: int = Depends(check_data_owner)):
    session = connect_db()
    obj = session.query(Object).filter(Object.object_id == object_id).first()
    if obj.owner_id != user_id:
        session.close()
        raise HTTPException(status_code=400, detail="You are not authorized to update this opject")
    if obj:
        obj.object_name = object_name
        obj.show = show
        obj.process = process
        obj.forward = forward
        obj.expire = expire
        session.commit()
        return {"Object updated success!!"}
    else:
        session.close()
        raise HTTPException(status_code=400, detail="Object not found")

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
async def read_users_me(current_user: str = Depends(current_user)):
    return {"current user is": current_user}


# list object type "user"
@app.get("/list_object/consent_method/user", tags=["End user"])
def list_objects(user_id: int = Depends(current_user)):
    session = connect_db()
    objects_user = session.query(Object).filter(Object.consent_method == "user").all()
    return objects_user


# Consent dataset
@app.post("/consent_object_dataset", tags=["End user"])
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
    return {"detail": obj_name}


# List consent_dataset 
@app.get("/list_user_consented", tags=["End user"])
def list_consented(user_id: int = Depends(current_user)):
    session = connect_db()
    consented = session.query(Consent_dataset).filter(Consent_dataset.user_id == user_id).all()
    if consented:
        return consented
    else:
        raise HTTPException(status_code=404, detail="Consented not found")

# revoke consent : update revoke_date
@app.put("/revoke/{consent_dataset_id}", tags=["End user"])
def update_revoke_date(consent_dataset_id: int, user_id: int = Depends(current_user)):
    session = connect_db()
    consent = session.query(Consent_dataset).filter(Consent_dataset.consent_dataset_id == consent_dataset_id, Consent_dataset.user_id == user_id).first()
    if consent is None:
        raise HTTPException(status_code=404, detail="Object not found or not consented by this user")
    if consent.revoke_date is None:
        consent.revoke_date = datetime.now()
        session.commit()
        session.close()
        return {"detail":"consent has been revoke"}
    else:
        raise HTTPException(status_code=404, detail="This object has been revoked")


# list object type "per_request"
@app.get("/list_object/consent_method/per_req", tags=["Data Consumer"])
def list_req():
    session = connect_db()
    objects = session.query(Object).filter(Object.consent_method == "per_request").all()
    obj_list = []
    for obj in objects:
        obj_list.append({"object_id": obj.object_id, "object_name": obj.object_name, "show": obj.show, "process": obj.process, "forward": obj.forward, "expire": obj.expire, "consent_method": obj.consent_method})
    return obj_list

# consent request
@app.post("/consent_request", tags=["Data Consumer"])
def consent_request(object_id: int, req_info: str, user_id: int = Depends(check_data_consumer)):
    session = connect_db()
    req_date = datetime.now()
    obj = session.query(Object).filter(Object.object_id == object_id).first()
    if obj is None:
        raise HTTPException(status_code=404, detail="Object not found")
    if obj.consent_method != "per_request":
        raise HTTPException(status_code=404, detail="Invalid consent method")
    existing_request = session.query(Consent_request).filter(Consent_request.object_id == object_id, Consent_request.consumer_id == user_id).first()
    if existing_request:
        raise HTTPException(status_code=400, detail="A consent request has been sent")
    end_user = session.query(UserAccount).filter(UserAccount.role_id == 1).all()
    for user in end_user:
        cs_req = Consent_request(request_date = req_date, request_info = req_info, object_id = obj.object_id, user_id = user.user_id, consumer_id = user_id)
        session.add(cs_req)
    session.commit()
    session.close()
    return {"A consent request has been sent to the End_User"}


# list consent request
@app.get("/list_request", tags=["End user"])
def list_consent_request(user_id: int = Depends(check_end_user)):
    session = connect_db()
    request = session.query(Consent_request).filter(and_(Consent_request.response == None, Consent_request.user_id == user_id)).all()
    if not request:
        raise HTTPException(status_code=404, detail="No consent request for this user")
    req_list = []
    for req in request:
        req_list.append({"request_id": req.request_id, "object_id": req.object_id, "user_id": req.user_id, "consumer_id": req.consumer_id, "request_date": req.request_date, "request_info": req.request_info, "response": req.response, "response_date": req.response_date})
    return req_list


# consent response
@app.put("/consent_response/{request_id}", tags=["End user"])
def consent_response(request_id: int,response: bool, user_id: int = Depends(check_end_user)):
    session = connect_db()
    res = session.query(Consent_request).filter(Consent_request.request_id == request_id).first()
    if res and res.user_id == user_id:
        res.response = response
        res.response_date = datetime.now()
        session.commit()
        session.close()
        return {"Consent request has been response"}
    else:
        raise HTTPException(status_code=404, detail="Consent request not found")



# จากตาราง consent_dataset 
@app.get("/check_consented", tags=["Data Consumer"])
def check_consented(object_id: int):
    session = connect_db()
    cs_user = session.query(Consent_dataset).filter(Consent_dataset.object_id == object_id).all()
    obj = session.query(Object).filter(Object.object_id == object_id).first()
    cs_list = []
    if cs_user:
        for day in cs_user:
            expire_day = obj.expire
            day.expire_date = day.consent_dataset_date + timedelta(days=expire_day)
            if day.expire_date < date.today():                
                continue
            cs_list.append({"object_id": day.object_id, "object_name": obj.object_name, "user_id": day.user_id, "consent_dataset_date": day.consent_dataset_date, "expire_date": day.expire_date})
        return cs_list
    else:
        raise HTTPException(status_code=404, detail="Object not found")


# list object type "always" + user_id ที่มี role "end_user"
@app.get("/list_object/always", tags=["Data Consumer"])
def list_consent_always():
    session = connect_db()
    objects = session.query(Object).filter(Object.consent_method == "always").all()
    end_users = session.query(UserAccount).filter(UserAccount.role_id == 1).all()
    obj_list = []
    for obj in objects:
        for user in end_users:
            obj_list.append({"object_id": obj.object_id, "object_name": obj.object_name, "user_id":user.user_id})
    return obj_list







