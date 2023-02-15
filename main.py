from datetime import date, datetime, timedelta
from typing import Union, Optional
from connect_database import connect_db

from fastapi import FastAPI, Depends, HTTPException, status

from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from pydantic import BaseModel
from login import create_access_token, SECRET_KEY, ALGORITHM
from jose import JWTError, jwt
from passlib.context import CryptContext
from services import Consent_dataset, Consent_element, Consent_request, Element, Element_request, Object, Roles, UserAccount
from enum import Enum
from crud import  check_data_consumer, check_end_user, current_user, check_data_owner, decode_token, get_current_user
from sqlalchemy.sql import and_


session = connect_db()

#
class Consent_method(str, Enum):
    always = "always"
    user = "user"
    per_req = "per_request"

# ของ Data owner
class list_element(str, Enum):
    none_element = "none element"
    element = "element"

# User_account
class Roles_method(str, Enum):
    end_user = "end_user"
    data_owner = "data_owner"
    data_consumer = "data_consumer"

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None

class User(BaseModel):
    username: str
    name: str
    role_id: int

#ของ End user
class Check_object_method(str, Enum):
    waiting_consent_object = "waiting consent object"
    waiting_consent_element = "waiting consent element"
    consented = "consented"
    expired = "expired"
    revoke = "revoked"
    consent_request = "consent request"
    element_request = "element request"
    response = "response"

# ของ Data consumer
class Check_response(str, Enum):
    response = "response"
    expired = "expired"

# ของ Data consumer
class List_object(str, Enum):
    all_object = "all object"
    per_req = "per request"
    response = "response"
    expired = "expired"

class UserInDB(User):
    hashed_password: str

# body parameter
class obj_field(BaseModel):
    name: Union[str, None] = None
    description: Union[str, None] = None


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


#register : TABLE user_account
@app.post("/register", tags=["System Admin"])
def register(username: str, password: str, name: str , role: Roles_method):
    session = connect_db()
    existing_user = session.query(UserAccount).filter(UserAccount.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists.")
    elif role == "end_user":
        hashed_password = pwd_context.hash(password)
        new_user = UserAccount(username=username, password=hashed_password, name=name, role_id=1)
        session.add(new_user)
        session.commit()
        return {"username": username, "name": name, "role": role}
    elif role == "data_owner":
        hashed_password = pwd_context.hash(password)
        new_user = UserAccount(username=username, password=hashed_password, name=name, role_id=2)
        session.add(new_user)
        session.commit()
        return {"username": username, "name": name, "role": role}    
    elif role == "data_consumer":
        hashed_password = pwd_context.hash(password)
        new_user = UserAccount(username=username, password=hashed_password, name=name, role_id=3)
        session.add(new_user)
        session.commit()
        return {"username": username, "name": name, "role": role}


# Login : TABLE user_account
@app.post("/token", tags=["System Admin"], response_model=Token)
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


# All object คือ แสดง object และ element ทั้งหมด 
# Per request คือ แสดงเฉพาะ object และ element ที่จะต้องขอ request ก่อนใช้งาน
# Response คือ แสดง response ที่ end user ตอบกลับ request
# Expired คือ แสดง response ที่หมดอายุ จะได้ขอ request ใหม่
@app.get("/list/method/consumer", tags=["Data Consumer"], description="สำหรับให้ data consumer ใช้ดูข้อมูลต่าง ๆ")
def list_object_consumer(check_method: List_object, user_id: int = Depends(check_data_consumer)):
    session = connect_db()
    if check_method == "all object":
        objects = session.query(Object).order_by(Object.object_id).all()
        object_list = []
        for obj in objects:
            elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
            ele_list = []
            if elements:
                for ele in elements:     
                    ele_list.append({"element_id": ele.element_id, "name": ele.name})
            object_list.append({"object_id": obj.object_id, "object_name": obj.object_name, "show": obj.show, "process": obj.process, "forward": obj.forward, "expire": obj.expire, "consent_method": obj.consent_method, "object_field": ele_list})
        session.close()
        return object_list


    if check_method == "per request":
        objects = session.query(Object).filter(Object.consent_method == "per_request").all()
        obj_list = []
        for obj in objects:
            elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
            ele_list = []
            if elements:
                for ele in elements:     
                    ele_list.append({"element_id": ele.element_id, "name": ele.name})
            obj_list.append({"object_id": obj.object_id, "object_name": obj.object_name, "show": obj.show, "process": obj.process, "forward": obj.forward, "expire": obj.expire, "consent_method": obj.consent_method, "object_field": ele_list})
        return obj_list

    if check_method == "response":
        responses = session.query(Consent_request).filter(Consent_request.consumer_id == user_id).all()
        response_list = []
        if responses:
            for res in responses:
                elements = session.query(Element).filter(Element.object_id == res.object_id).all()
                ele_list = []
                for ele in elements:
                    element_request = session.query(Element_request).filter(Element_request.consumer_id == user_id, Element_request.element_id == ele.element_id, Element_request.user_id == res.user_id).all()
                    for ele_req in element_request:
                        if ele_req.response is None:
                            continue
                        ele_list.append({"element_id": ele.element_id, "name": ele.name, "response":ele_req.response})
                if res.response is not None:
                    obj = session.query(Object).filter(Object.object_id == res.object_id).first()
                    if obj: 
                        expire_date = res.response_date + timedelta(days=obj.expire)
                        if expire_date < date.today():
                            continue
                        else:
                            status = "valid"
                        user = session.query(UserAccount).filter(UserAccount.user_id == res.user_id).first()
                        response_list.append({"object_id": obj.object_id, "object_name": obj.object_name,"user_id": res.user_id,"user_name":user.name, "request_id": res.request_id, "response": res.response, "response_date": res.response_date, "expire_date": expire_date, "status": status, "consumer_id": res.consumer_id, "object_field":ele_list})
        if not response_list:
            raise HTTPException(status_code=404, detail="No consent response found.")
        else:
            return response_list
            
    elif check_method == "expired":
        responses = session.query(Consent_request).filter(Consent_request.consumer_id == user_id).all()
        response_list = []
        for res in responses:
            elements = session.query(Element).filter(Element.object_id == res.object_id).all()
            ele_list = []
            for ele in elements:
                element_request = session.query(Element_request).filter(Element_request.consumer_id == user_id, Element_request.element_id == ele.element_id, Element_request.user_id == res.user_id).all()
                for ele_req in element_request:
                    if ele_req.response is None:
                        continue
                    ele_list.append({"element_id": ele.element_id, "name": ele.name, "response":ele_req.response})
            if res.response is not None:
                obj = session.query(Object).filter(Object.object_id == res.object_id).first()
                if obj:
                    expire_day = obj.expire
                    expire_date = res.response_date + timedelta(days=expire_day)
                    if expire_date < date.today():
                        status = 'expired'
                        user = session.query(UserAccount).filter(UserAccount.user_id == res.user_id).first()
                        response_list.append({"object_id": obj.object_id, "object_name": obj.object_name, "user_id":res.user_id, "user_name":user.name, "request_id": res.request_id, "response": res.response, "reseponse_date": res.response_date, "expire_date": expire_date, "status": status,"consumer_id": res.consumer_id, "object_field":ele_list})
        if not response_list:
            raise HTTPException(status_code=404, detail="No expired consent response found.")
        else:
            return response_list
    else:
        session.close()
        raise HTTPException(status_code=400, detail="Invalid `check_method` parameter.")


# API check object ที่ end_user ให้ consent และ response ของ data_consumer
@app.get("/check/consent/id/{object_id}", tags=["Data Consumer"], description="สำหรับให้ data consumer ดูว่าแต่ละ object มี user ไหน ให้ consent แล้วบ้าง")
def list_consented(object_id: int, user_id: int = Depends(check_data_consumer)):
    session = connect_db()
    object = session.query(Object).filter(Object.object_id == object_id).first()
    end_users = session.query(UserAccount).filter(UserAccount.role_id == 1).all()
    obj_user = session.query(Consent_dataset).filter(Consent_dataset.object_id == object_id).all()
    obj_req = session.query(Consent_request).filter(Consent_request.object_id == object_id, Consent_request.consumer_id == user_id).all()
    cs_list = []
    if object is None:
        raise HTTPException(status_code=404, detail="Object not found.")

    elif obj_user:
        for cs in obj_user:
            consented = session.query(Consent_dataset).filter(Consent_dataset.user_id == cs.user_id).all()
            for obj in consented:
                elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
                list_element = []
                for ele in elements:
                    if session.query(Consent_element).filter(Consent_element.user_id == cs.user_id, Consent_element.element_id == ele.element_id).first():
                        list_element.append({"element_id": ele.element_id, "name": ele.name})
            if cs.revoke_date:
                continue
            expire_day = object.expire
            expire_date = cs.consent_dataset_date + timedelta(days=expire_day)
            if expire_date < date.today():
                continue
            users = session.query(UserAccount).filter(UserAccount.user_id == cs.user_id).first()
            cs_list.append({"object_id": cs.object_id, "object_name": object.object_name, "user_id": cs.user_id,"user_name": users.name, "consent_dataset_date": cs.consent_dataset_date,"expire":object.expire, "expire_date": expire_date, "object_field":list_element})
        return {"total_user":len(cs_list), "consented_objects": cs_list}

    elif obj_req:
        for res in obj_req:
            elements = session.query(Element).filter(Element.object_id == res.object_id).all()
            ele_list = []
            for ele in elements:
                element_request = session.query(Element_request).filter(Element_request.consumer_id == user_id, Element_request.element_id == ele.element_id, Element_request.user_id == res.user_id).all()
                for ele_req in element_request:
                    if ele_req.response is None:
                        continue
                    ele_list.append({"element_id": ele.element_id, "name": ele.name, "response":ele_req.response})
            if res.response_date is not None:
                expire_day = object.expire
                expire_date = res.response_date + timedelta(days=expire_day)
                if expire_date < date.today():
                    continue
                users = session.query(UserAccount).filter(UserAccount.user_id == res.user_id).first()            
                cs_list.append({"object_id":res.object_id, "object_name":object.object_name,"request_id":res.request_id, "user_id":res.user_id,"user_name": users.name, "response":res.response, "response_date":res.response_date,"expire":object.expire, "expire_date":expire_date, "consumer_id":res.consumer_id, "object_field":ele_list})
        return {"total_user":len(cs_list), "consented_objects": cs_list}

    elif object.consent_method == "always":
        for user in end_users:
            cs_list.append({"object_id": object.object_id, "object_name": object.object_name, "user_id": user.user_id, "user_name": user.name})
        return {"total_user":len(cs_list), "consented_objects": cs_list}
    else: 
        raise HTTPException(status_code=404, detail="consent not found.")


# consent request
@app.post("/request/consent/object", tags=["Data Consumer"], description="สำหรับให้ data consumer ขอ request object: per_req")
def consent_request(object_id: int, req_info: str, user_id: int = Depends(check_data_consumer)):
    session = connect_db()
    req_date = datetime.now()
    obj = session.query(Object).filter(Object.object_id == object_id).first()
    if obj is None:
        raise HTTPException(status_code=404, detail="Object not found")
    if obj.consent_method != "per_request":
        raise HTTPException(status_code=404, detail="Invalid consent method")
    end_users = session.query(UserAccount).filter(UserAccount.role_id == 1).all()
    posted_user_ids = [cs_req.user_id for cs_req in session.query(Consent_request).filter(Consent_request.object_id == object_id, Consent_request.consumer_id == user_id).all()]
    for user in end_users:
        if user.user_id in posted_user_ids:
            continue
        cs_req = Consent_request(request_date = req_date, request_info = req_info, object_id = obj.object_id, user_id = user.user_id, consumer_id = user_id)
        session.add(cs_req)
    session.commit()
    session.close()
    return {"message":"A consent request has been sent to the End_User"}


# update request ของ consumer กรณีที่ response expired
@app.put("/update/object/request/{request_id}", tags=["Data Consumer"], description="สำหรับให้ data consumer update request กรณีที่ response จาก end user นั้น expired ")
def update_request(request_id: int, user_id: int = Depends(check_data_consumer)):
    session = connect_db()
    request = session.query(Consent_request).filter(Consent_request.request_id == request_id, Consent_request.consumer_id == user_id).first()
    if request is None:
        raise HTTPException(status_code=404, detail="Object not found")
    if request.request_date is not None:
        request.request_date = datetime.now()
        request.response = None
        request.response_date = None
        session.commit()
        session.close()
        return {"message":"request has been update"}

# list object
@app.get("/list/method/owner", tags=["Data Owner"], description="สำหรับให้ data owner ดูว่าเพิ่มข้อมูลอะไรไปแล้วบ้าง")
def list_object(check_method: list_element, user_id:int = Depends(check_data_owner)):
    session = connect_db()
    objects = session.query(Object).filter(Object.owner_id == user_id).all()
    obj_list = []
    if check_method == "none element":
        if objects:
            for obj in objects:
                elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
                if not elements:
                    obj_list.append({"object_id":obj.object_id, 
                                 "object_name": obj.object_name, 
                                 "show": obj.show,
                                 "process": obj.process,
                                 "forward": obj.forward,
                                 "expire": obj.expire,
                                 "consent_method": obj.consent_method})
            if not obj_list:
                raise HTTPException(status_code=404, detail="object not found.")
            else:
                return obj_list
        else:
            raise HTTPException(status_code=404, detail="object not found.")

    elif check_method == "element":
        if objects:
            for obj in objects:
                elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
                ele_list = []
                if elements:
                    for ele in elements:     
                        ele_list.append({"element_id": ele.element_id, "name": ele.name})
                    obj_list.append({
                    "object_id": obj.object_id,
                    "object_name": obj.object_name,
                    "object_field": ele_list,
                    "show": obj.show,
                    "process": obj.process,
                    "forward": obj.forward,
                    "expire": obj.expire,
                    "consent_method": obj.consent_method})
            if not obj_list:
                raise HTTPException(status_code=404, detail="object not found.")
            else:
                return obj_list
        else:
            raise HTTPException(status_code=404, detail="object not found.")

# inset object
@app.post("/insert/object", tags=["Data Owner"], description="สำหรับให้ data owner ใช้เพิ่มข้อมูล (object)")
def insert_object(object_name: str, show:bool, process:bool, forward:bool, consent_method: Consent_method, expire: Optional[int] = None, owner_id: int = Depends(check_data_owner)):
    session = connect_db()
    if consent_method in ["user", "per_request"]:
        if expire is None:
            raise HTTPException(status_code=400, detail="Expire value is required for user and per_request consent methods")
    new_object = Object(object_name=object_name, owner_id = owner_id, show=show, process=process, forward=forward, expire=expire, consent_method=consent_method)
    session.add(new_object)
    session.commit()
    session.close()
    return {"message":"Object insert success!!"}

# update object
@app.put("/update/object", tags=["Data Owner"], description="สำหรับให้ data owner ใช้แก้ไขข้อมูลที่เคยเพิ่ม")
def update_object(object_id: int, object_name: str, show: bool, process: bool, forward: bool, consent_method: Consent_method,expire: Optional[int] = None, user_id: int = Depends(check_data_owner)):
    session = connect_db()
    obj = session.query(Object).filter(Object.object_id == object_id).first()
    if obj.owner_id != user_id:
        session.close()
        raise HTTPException(status_code=400, detail="You are not authorized to update this object")
    if obj:
        if consent_method in ["user", "per_request"]:
            if expire is None:
                raise HTTPException(status_code=400, detail="Expire value is required for user and per_request consent methods")
        elif consent_method in ["always"]:
            expire = None
        obj.object_name = object_name
        obj.show = show
        obj.process = process
        obj.forward = forward
        obj.expire = expire
        obj.consent_method=consent_method
        session.commit()
        return {"message":"update object success."}
    else:
        session.close()
        raise HTTPException(status_code=400, detail="Object not found")


@app.delete("/delete/object/{object_id}", tags=["Data Owner"], description="สำหรับให้ data owner ใช้ลบข้อมูลที่เคยเพิ่ม")
def delete_object(object_id: int, user_id: int = Depends(current_user)):
    session = connect_db()
    obj = session.query(Object).filter(Object.object_id == object_id).first()
    if obj and obj.owner_id == user_id:
        session.delete(obj)
        session.commit()
        return {"message":"Object deleted success!!"}
    if obj and obj.owner_id != user_id:
        session.close()
        raise HTTPException(status_code=400, detail="You are not authorized to delete this object")
    else:
        session.close()
        raise HTTPException(status_code=400, detail="Object not found")


# insert element
@app.post("/insert/element", tags=["Data Owner"], description="สำหรับให้ data owner ใช้เพิ่ม element ของ object")
def insert_element(object_id: int,name: str, user_id: int = Depends(check_data_owner)):
    session = connect_db()
    object = session.query(Object).filter(Object.object_id == object_id, Object.owner_id == user_id).first()
    if object is not None:
        new_element = Element(name = name, object_id = object_id, owner_id = user_id)
        session.add(new_element)
        session.commit()
        session.close()
        return {"message":"insert object element success."}
    else:
        raise HTTPException(status_code=404, detail="Object not found or not inserted by this user.")
    
# update element
@app.put("/update/element", tags=["Data Owner"], description="สำหรับให้ data owner ใช้แก้ไข element ที่เคยเพิ่ม")
def update_element(element_id: int, name: str, user_id: int = Depends(check_data_owner)):
    session = connect_db()
    element = session.query(Element).filter(Element.element_id == element_id).first()
    if element is None:
        raise HTTPException(status_code=404, detail="Element not found.")
    if element.owner_id != user_id:
        session.close()
        raise HTTPException(status_code=400, detail="You are not authorized to update this element")
    element.name = name
    session.commit()
    return {"message":"Element updated successfully."}


@app.delete("/delete/element/{element_id}", tags=["Data Owner"], description="สำหรับให้ data owner ใช้ลบ element ที่เคยเพิ่ม")
def delete_object(element_id: int, user_id: int = Depends(current_user)):
    session = connect_db()
    element = session.query(Element).filter(Element.element_id == element_id).first()
    if element and element.owner_id == user_id:
        session.delete(element)
        session.commit()
        return {"message":"Element deleted successfully."}
    if element and element.owner_id != user_id:
        session.close()
        raise HTTPException(status_code=400, detail="You are not authorized to delete this element.")
    else:
        session.close()
        raise HTTPException(status_code=400, detail="Element not found.")



# Waiting consent object คือ แสดง object: user ที่ยังไม่ได้ให้ consent
# Waiting consent element คือ แสดง element ของ object ที่ให้ consent ไป 
# Consented คือ แสดง object และ element ที่ consent ไปแล้ว
# Expired คือ แสดง object และ element ที่ expired
# Revoked คือ แสดง object และ element ที่ end user ได้ revoke ไปแล้ว
# Consent request คือ แสดง request ของ object ที่ data consumer ขอ request มา
# Element request คือ แสดง request ของ element ที่ data consumer ของ request มา
# Response คือ แสดง object และ element ที่ end user ได้ response กลับ
@app.get("/list/method/user", tags=["End user"], description="สำหรับให้ end user ใช้ดูข้อมูลต่าง ๆ")
def list_consented(check_method: Check_object_method, user_id: int = Depends(check_end_user)):
    session = connect_db()
    if check_method == "waiting consent object":
        objects_user = session.query(Object).filter(Object.consent_method == "user").all()
        consented_objects = session.query(Consent_dataset).filter(Consent_dataset.user_id == user_id).all()
        non_consented_objects = []
        for obj in objects_user:
            found = False
            for consented_obj in consented_objects:
                if obj.object_id == consented_obj.object_id:
                    found = True
                    break
            if not found:
                non_consented_objects.append({"object_id": obj.object_id, "object_name": obj.object_name, "show": obj.show, "process": obj.process, "forward": obj.forward})
        if not non_consented_objects:
            raise HTTPException(status_code=404, detail="not found object")
            #return "no object"
        else:
            return non_consented_objects
        
    if check_method == "waiting consent element":
        object_consented = session.query(Consent_dataset).filter(Consent_dataset.user_id == user_id).all()
        list_consented = []
        if object_consented:
            for obj in object_consented:
                object_ = session.query(Object).filter(Object.object_id == obj.object_id).first()
                elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
                list_element = []
                for ele in elements:
                    if not session.query(Consent_element).filter(Consent_element.user_id == user_id, Consent_element.element_id == ele.element_id).first():
                        list_element.append({"element_id": ele.element_id, "name": ele.name})
                if list_element:
                    list_consented.append({"object_id": obj.object_id, "object_name": object_.object_name, "object_field": list_element})
            if list_consented:
                return list_consented
            else:
                raise HTTPException(status_code=404, detail="No object element")
        else:
            raise HTTPException(status_code=404, detail="Consent was not found.")
        
    if check_method == "consented":
        consented = session.query(Consent_dataset).filter(Consent_dataset.user_id == user_id).all()
        consented_list = []
        if consented:
            for obj in consented:
                if obj.revoke_date is not None:
                    continue
                objects = session.query(Object).filter(Object.object_id == obj.object_id).first()
                elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
                list_element = []
                for ele in elements:
                    if session.query(Consent_element).filter(Consent_element.user_id == user_id, Consent_element.element_id == ele.element_id).first():
                        list_element.append({"element_id": ele.element_id, "name": ele.name})
                expire_day = objects.expire
                expire_date = obj.consent_dataset_date + timedelta(days=expire_day)
                if expire_date < date.today():
                    continue
                else:
                    status = 'valid'
                consented_list.append({"object_id":objects.object_id,"object_name": objects.object_name,"consent_dataset_id":obj.consent_dataset_id,"consent_dataset_date":obj.consent_dataset_date,"expire_date":expire_date,"status":status, "object_field": list_element})
        if not consented_list:
            raise HTTPException(status_code=404,detail="No consented data found")
        else:            
            return consented_list
        
    if check_method == "expired":
        responses = session.query(Consent_request).filter(Consent_request.user_id == user_id).all()
        consented = session.query(Consent_dataset).filter(Consent_dataset.user_id == user_id).all()
        consented_list = []
        if consented:
            for obj in consented:
                if obj.revoke_date is not None:
                    continue
                objects = session.query(Object).filter(Object.object_id == obj.object_id).first()
                elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
                list_element = []
                for ele in elements:
                    if session.query(Consent_element).filter(Consent_element.user_id == user_id, Consent_element.element_id == ele.element_id).first():
                        list_element.append({"element_id": ele.element_id, "name": ele.name})
                expire_day = objects.expire
                expire_date = obj.consent_dataset_date + timedelta(days=expire_day)
                if expire_date < date.today():
                    status = 'expired'
                    consented_list.append({"object_id":objects.object_id,"object_name": objects.object_name,"consent_dataset_id":obj.consent_dataset_id,"consent_dataset_date":obj.consent_dataset_date,"expire_date":expire_date,"status":status, "object_field": list_element})
            for res in responses:
                if res.response is not None:
                    obj = session.query(Object).filter(Object.object_id == res.object_id).first()
                    expire_day = obj.expire
                    expire_date = res.response_date + timedelta(days=expire_day)
                    elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
                    list_element = []
                    for ele in elements:
                        element_request = session.query(Element_request).filter(Element_request.user_id == user_id, Element_request.element_id == ele.element_id).all()
                        for ele_req in element_request:
                            if ele_req.response is None:
                                    continue
                            list_element.append({"element_id": ele.element_id, "name": ele.name, "response":ele_req.response})
                    if expire_date < date.today():
                        status = 'expired'
                        consented_list.append({"object_id": obj.object_id, "object_name": obj.object_name, "request_id": res.request_id, "response": res.response, "reseponse_date": res.response_date, "expire_date":expire_date, "status":status,"consumer_id": res.consumer_id, "object_field":list_element})
        if not consented_list:
            raise HTTPException(status_code=404,detail="No expired consented data found")
        else:
            return consented_list

    if check_method == "revoked":
        consented = session.query(Consent_dataset).filter(Consent_dataset.user_id == user_id).all()
        consented_list = []
        if consented:
            for obj in consented:
                if obj.revoke_date is None:
                    continue
                else:
                    status = 'revoked'
                objects = session.query(Object).filter(Object.object_id == obj.object_id).first()
                elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
                list_element = []
                for ele in elements:
                    if session.query(Consent_element).filter(Consent_element.user_id == user_id, Consent_element.element_id == ele.element_id).first():
                        list_element.append({"element_id": ele.element_id, "name": ele.name})
                consented_list.append({"object_id":objects.object_id,"object_name": objects.object_name,"consent_dataset_id":obj.consent_dataset_id,"consent_dataset_date":obj.consent_dataset_date,"revoke_date":obj.revoke_date, "status":status, "object_field": list_element})
        if not consented_list:
            raise HTTPException(status_code=404,detail="No revoked consented data found")
        else:
            return consented_list
        
    if check_method == "consent request":
        request = session.query(Consent_request).filter(and_(Consent_request.response == None, Consent_request.user_id == user_id)).all()
        if not request:
            raise HTTPException(status_code=404, detail="No consent request for this user")
        req_list = []
        for req in request:
            obj = session.query(Object).filter(Object.object_id == req.object_id).first()
            users = session.query(UserAccount).filter(UserAccount.user_id == req.consumer_id).first()
            req_list.append({"request_id": req.request_id, "object_id": req.object_id, "object_name": obj.object_name, "consumer_id": req.consumer_id, "consumer_name": users.name, "request_date": req.request_date, "request_info": req.request_info})
        return req_list
    
    if check_method == "element request":
        request = session.query(Element_request).filter(and_(Element_request.response == None, Element_request.user_id == user_id)).all()
        if not request:
            raise HTTPException(status_code=404, detail="No consent element request for this user")
        req_list = []
        for req in request:
            obj = session.query(Element).filter(Element.element_id == req.element_id).first()
            req_list.append({"request_element_id": req.req_element_id, "element_id": req.element_id, "name": obj.name, "consumer_id": req.consumer_id})
        return req_list

    if check_method == "response":
        responses = session.query(Consent_request).filter(Consent_request.user_id == user_id).all()
        consented_list = []
        if responses:
            for res in responses:
                if res.response is not None:
                    obj = session.query(Object).filter(Object.object_id == res.object_id).first()
                    elements = session.query(Element).filter(Element.object_id == obj.object_id).all()
                    list_element = []
                    for ele in elements:
                        element_request = session.query(Element_request).filter(Element_request.user_id == user_id, Element_request.element_id == ele.element_id).all()
                        for ele_req in element_request:
                            if ele_req.response is None:
                                    continue
                            list_element.append({"element_id": ele.element_id, "name": ele.name, "response":ele_req.response})
                    expire_day = obj.expire
                    expire_date = res.response_date + timedelta(days=expire_day)
                    if expire_date < date.today():
                        status = 'expired'
                    else:
                        status = 'valid'
                    if obj:
                        consented_list.append({"object_id": obj.object_id, "object_name": obj.object_name, "request_id": res.request_id, "response": res.response, "reseponse_date": res.response_date, "expire_date":expire_date, "status":status,"consumer_id": res.consumer_id, "object_field":list_element})
        if not consented_list:
            raise HTTPException(status_code=404, detail="No consent response found.")
        else:
            return consented_list
    else:
        raise HTTPException(status_code=404,detail="No consented data found")


@app.post("/consent/object/{object_id}", tags=["End user"], description="สำหรับให้ end user ใช้ consent object: user")
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
    obj_name = obj.object_name
    consent = Consent_dataset(consent_dataset_date = cs_date, user_id = user_id, object_id = object_id)
    session.add(consent)
    session.commit()
    session.close()
    return {"consented": obj_name}


@app.post("/consent/element/{element_id}", tags=["End user"], description="สำหรับให้ end user ใช่ consent element ของ object ที่ consent ไปแล้ว")
def consent_element(element_id: int, user_id: int = Depends(current_user)):
    session = connect_db()
    elements = session.query(Element).filter(Element.element_id == element_id).first()
    if elements is None:
        session.close()
        raise HTTPException(status_code=404, detail="Element not found.")

    object_id = elements.object_id
    object_consented = session.query(Consent_dataset).filter(Consent_dataset.user_id == user_id, Consent_dataset.object_id == object_id).first()
    if object_consented is None:
        session.close()
        raise HTTPException(status_code=400, detail="Please consent the object first.")

    existing_consent = session.query(Consent_element).filter(Consent_element.element_id == element_id, Consent_element.user_id == user_id).first()
    if existing_consent:
        session.close()
        raise HTTPException(status_code=400, detail="This element has been consented.")

    element_name = elements.name
    consent = Consent_element(element_id=element_id, user_id=user_id)
    session.add(consent)
    session.commit()
    session.close()
    return {"consented": element_name}


@app.delete("/delete/element/user/{element_id}", tags=["End user"], description="สำหรับให้ end user ใช้ลบ element ที่เคยให้ consent ไป ในกรณีที่ต้องการยกเลิก consent element นั้น ๆ ")
def delete_element(element_id: int,user_id: int = Depends(check_end_user)):
    session = connect_db()
    consent = session.query(Consent_element).filter(Consent_element.user_id == user_id, Consent_element.element_id == element_id).first()
    if consent:
        session.delete(consent)
        session.commit()
        return {"message":"Element has been deleted."}
    else:
        raise HTTPException(status_code=404, detail="Element not found.")


# update consent เผื่อเวลาที่ object ที่เคยให้ไปหมดอายุ และยกเลิก revoked consent 
@app.put("/update/consent/{consent_dataset_id}", tags=["End user"], description="สำหรับให้ end user มา update consent กรณีที่ object ที่เคยให้ไป expired หรือทำการ revoke ไปแล้ว")
def update_consent(consent_dataset_id: int, user_id: int = Depends(check_end_user)):
    session = connect_db()
    consent = session.query(Consent_dataset).filter(Consent_dataset.consent_dataset_id == consent_dataset_id, Consent_dataset.user_id == user_id).first()
    if consent is None:
        raise HTTPException(status_code=404, detail="Consent not found or not consented by this user.")
    consent.consent_dataset_date = datetime.now()
    consent.revoke_date = None
    session.commit()
    session.close()
    return {"message":"Consent has been updated."}


# revoke consent : update revoke_date
@app.put("/revoke/consent/{consent_dataset_id}", tags=["End user"], description="สำหรับให้ end user ถอน consent ")
def update_revoke_date(consent_dataset_id: int, user_id: int = Depends(current_user)):
    session = connect_db()
    consent = session.query(Consent_dataset).filter(Consent_dataset.consent_dataset_id == consent_dataset_id, Consent_dataset.user_id == user_id).first()
    if consent is None:
        raise HTTPException(status_code=404, detail="Object not found")
    if consent.revoke_date is None:
        consent.revoke_date = datetime.now()
        session.commit()
        session.close()
        return {"message":"consent has been revoke"}
    else:
        raise HTTPException(status_code=400, detail="This object has been revoked")


@app.put("/consent/response/object", tags=["End user"], description="สำหรับให้ end user มา response object ที่ consumer ขอ request มา")
def consent_response(request_id: int,response: bool, user_id: int = Depends(check_end_user)):
    session = connect_db()
    res = session.query(Consent_request).filter(Consent_request.request_id == request_id).first()
    if res and res.user_id == user_id:
        res.response = response
        res.response_date = datetime.now()
        session.commit()
        session.close()
        return {"message":"Consent request has been response"}
    else:
        raise HTTPException(status_code=404, detail="Consent request not found")


# end user
@app.put("/consent/response/element", tags=["End user"], description="สำหรับให้ end user มา response element ที่ consumer ขอ request มา")
def consent_response(req_element_id: int, response: bool, user_id: int = Depends(check_end_user)):
    session = connect_db()
    res = session.query(Element_request).filter(Element_request.req_element_id == req_element_id).first()
    if res is None:
        raise HTTPException(status_code=404, detail="Consent element request not found.")
    res_cs = session.query(Consent_request).filter(Consent_request.request_id == res.req_consent_id).first()
    if res.user_id != user_id:
        raise HTTPException(status_code=400, detail="You are not the owner of this request.")
    if res_cs.response is None:
        raise HTTPException(status_code=400, detail="Please consent object first.")
    if res_cs.response is False:
        raise HTTPException(status_code=400, detail="Object request has been denied.")
    res.response = response
    session.commit()
    session.close()
    return {"message":"Consent element request has been responded."}

    

@app.post("/request/consent/element/{element_id}", tags=["Data Consumer"], description="สำหรับให้ data consumer ขอ request element ของ object ที่ขอ request ไป")
def consent_request(element_id: int, user_id: int = Depends(check_data_consumer)):
    session = connect_db()
    req_date = datetime.now()
    ele = session.query(Element).filter(Element.element_id == element_id).first()
    obj = session.query(Object).filter(Object.object_id == ele.object_id).first()
    res_cs = session.query(Consent_request).filter(Consent_request.object_id == obj.object_id, Consent_request.consumer_id == user_id).first()
    if ele is None:
        raise HTTPException(status_code=404, detail="Object not found")
    if obj.consent_method != "per_request":
        raise HTTPException(status_code=404, detail="Invalid consent method")
    if res_cs is None:
        raise HTTPException(status_code=400, detail="Please request object first.")
    end_users = session.query(UserAccount).filter(UserAccount.role_id == 1).all()
    posted_user_ids = [cs_req.user_id for cs_req in session.query(Element_request).filter(Element_request.element_id == element_id, Element_request.consumer_id == user_id).all()]
    for user in end_users:
        if user.user_id in posted_user_ids:
            continue
        req_consent_id = session.query(Consent_request).filter(Consent_request.user_id == user.user_id, Consent_request.consumer_id == user_id).first().request_id
        ele_req = Element_request(element_id=ele.element_id, user_id=user.user_id, consumer_id=user_id, req_consent_id=req_consent_id)
        session.add(ele_req)
    session.commit()
    session.close()
    return {"message": "A request has been sent to the End_User"}

    


