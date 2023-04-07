import time
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from db_settings import get_db_url
from sqlalchemy_utils import database_exists, create_database

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(255),unique=True)
    password = Column(String(255))
    description = Column(String(255))
    totp_secret = Column(String(255))

not_ready = True
url = get_db_url()
while(not_ready):
    try:
        if not database_exists(url):
            create_database(url)
        engine = create_engine(get_db_url(), pool_size=75, max_overflow=0)
        Base.metadata.create_all(bind=engine)
        not_ready = False
        print("Database ready", flush=True)
    except Exception as ex:
        print (ex, flush=True)
        print("Database not ready", flush=True)
        time.sleep(5)
        pass
