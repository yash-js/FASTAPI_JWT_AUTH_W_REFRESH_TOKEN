
from sqlmodel import SQLModel, create_engine, Session
from models.user import User
from models.refresh_token import RefreshToken
import os
from dotenv import load_dotenv
load_dotenv()

engine = create_engine(os.getenv("DB_URL"))

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
    
    
def get_session():
    with Session(engine) as session:
        yield session