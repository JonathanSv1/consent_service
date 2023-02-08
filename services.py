from sqlalchemy import Column, Integer, String, ForeignKey, Date, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import JSON


Base = declarative_base()

class Roles(Base):
    __tablename__ = 'roles'
    role_id = Column(Integer, primary_key=True)
    role_name = Column(String, unique=True)

class UserAccount(Base):
    __tablename__ = 'user_account'
    user_id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    name = Column(String)
    role_id = Column(Integer, ForeignKey(Roles.role_id))

class Object(Base):
    __tablename__ = 'object_dataset'
    object_id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey(UserAccount.user_id))
    object_name = Column(String)
    show = Column(Boolean)
    process = Column(Boolean)
    forward = Column(Boolean)
    expire = Column(Integer)
    consent_method = Column(String)

class Consent_dataset(Base):
    __tablename__ = 'consent_dataset'
    consent_dataset_id = Column(Integer, primary_key=True)
    consent_dataset_date = Column(Date)
    user_id = Column(Integer, ForeignKey(UserAccount.user_id))
    object_id = Column(Integer, ForeignKey(Object.object_id))
    revoke_date = Column(Date)

class Consent_request(Base):
    __tablename__ = 'consent_request'
    request_id = Column(Integer, primary_key=True)
    request_date = Column(Date)
    request_info = Column(String)
    object_id = Column(Integer, ForeignKey(Object.object_id))
    user_id = Column(Integer, ForeignKey(UserAccount.user_id))
    response = Column(Boolean)
    response_date = Column(Date)
    consumer_id = Column(Integer, ForeignKey(UserAccount.user_id))

class Element(Base):
    __tablename__ = 'object_element'
    element_id = Column(Integer, primary_key=True)
    name = Column(String)
    object_id = Column(Integer, ForeignKey(Object.object_id))
    owner_id = Column(Integer, ForeignKey(UserAccount.user_id))

class Consent_element(Base):
    __tablename__ = 'consent_element'
    consent_element_id = Column(Integer, primary_key=True)
    element_id = Column(Integer, ForeignKey(Element.element_id))
    user_id = Column(Integer, ForeignKey(UserAccount.user_id))

class Element_request(Base):
    __tablename__ = 'element_request'
    req_element_id = Column(Integer, primary_key=True)
    element_id = Column(Integer, ForeignKey(Element.element_id))
    user_id = Column(Integer, ForeignKey(UserAccount.user_id))
    response = Column(Boolean)
    consumer_id = Column(Integer, ForeignKey(UserAccount.user_id))
    req_consent_id = Column(Integer, ForeignKey(Consent_request.request_id))
