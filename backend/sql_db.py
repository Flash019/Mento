
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from config import DATABASE_URL

Database_url = DATABASE_URL
engine = create_engine(Database_url, pool_pre_ping=True,echo=True) # echo=True Means ---> Show all the commands or outputs in the console for debugging 

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False) # Create a factory that makes new database sessions connected to engine 
# Engine --> know how to talk to the data base 
# SessionLocal() --> know where to connect , because its bound to engine 


Base = declarative_base()  # Create a base class for all my ORM models to inherit from
# Base Holds metadeta and ORM mapping information .

def get_db ():
    db = SessionLocal() # Opens a session you can use to run queries 
    try:
        yield db # give session to the endpoint 
    finally:
        db.close()  # runs after request is done   


