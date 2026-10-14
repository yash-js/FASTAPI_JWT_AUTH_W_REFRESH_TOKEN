from fastapi import FastAPI
from contextlib import asynccontextmanager
from database import create_db_and_tables
from routes.users import router as user_routes
from routes.auth import router as auth_routes

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(title="Auth API using JWT", description="Authentication API usign JWT with Login and Sign up routes", lifespan=lifespan)

app.include_router(user_routes)
app.include_router(auth_routes)





@app.get("/", tags=["Root"])
def home():
    return {"message":"Hello world!"}