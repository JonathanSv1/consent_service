from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

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
    __tablename__ = 'object'
    object_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey(UserAccount.user_id))
    object_name = Column(String)
    object_field = Column(String)
    show = Column(Integer)
    process = Column(Integer)
    forward = Column(Integer)
    expire = Column(Integer)
    consent_method = Column(String)