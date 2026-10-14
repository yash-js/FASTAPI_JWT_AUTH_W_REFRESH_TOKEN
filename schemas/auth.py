from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str
    
class SignupRequest(BaseModel):
    username: str
    password: str
    
class RefreshRequest(BaseModel):
    refresh_token:str