from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Object(Base):
    __tablename__ = 'object'
    object_id = Column(Integer, primary_key=True)
    object_name = Column(String)
    show = Column(Integer)
    process = Column(Integer)
    forward = Column(Integer)
    expire = Column(Integer)

class UserAccount(Base):
    __tablename__ = 'user_account'
    user_id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    name = Column(String)
    role_id = Column(Integer)

class Roles(Base):
    __tablename__ = 'roles'
    role_id = Column(Integer, primary_key=True)
    role_name = Column(String, unique=True)
