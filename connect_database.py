from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def connect_db():
    # create a SQLAlchemy engine
    engine = create_engine("postgresql://postgres:123456789@localhost/Consent_service")
    # create a session factory
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    # return the session
    return SessionLocal()
