from pydantic import BaseModel, EmailStr, ConfigDict
from datetime import datetime

# --- INPUT SCHEMAS ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# --- OUTPUT SCHEMAS ---

# 3.1 Account Creation Schema
class UserRegistrationResponse(BaseModel):
    id: int               
    email: EmailStr       
    is_active: bool = True 
    is_superuser: bool = False 
    created_at: datetime  
    model_config = ConfigDict(from_attributes=True)

# 3.2 Secure Authentication Token Schema
class TokenExchangeResponse(BaseModel):
    access_token: str     
    refresh_token: str    
    token_type: str = "bearer"

# 3.3 Standard Operational Message Schema
class StandardActionResponse(BaseModel):
    detail: str