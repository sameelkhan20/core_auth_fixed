from fastapi import APIRouter, Depends, HTTPException, status, Request
import time
import jwt
from pydantic import BaseModel
from app.schemas import TokenExchangeResponse, StandardActionResponse, UserLogin

# Security functions aur secrets import kar rahe hain
from app.security import (
    verify_password, 
    create_access_token, 
    create_refresh_token, 
    REFRESH_TOKEN_SECRET, 
    ALGORITHM
)
# dependencies.py se naya security_scheme import kar rahe hain
from app.dependencies import security_scheme

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Refresh token receive karne ke liye input model
class TokenRefreshRequest(BaseModel):
    refresh_token: str

@router.post("/login", response_model=TokenExchangeResponse)
async def login(user_data: UserLogin, request: Request):
    """
    The Authentication Step: Submit credentials, verify password, 
    and return dual tokens (Access & Refresh)[cite: 45, 46].
    """
    db_pool = request.app.state.db_pool
    
    # User fetch karo (Non-blocking I/O)
    user = await db_pool.fetchrow("SELECT * FROM users WHERE email = $1", user_data.email)
    
    if not user or not verify_password(user_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect email or password"
        )
        
    # Dual-Token Key Separation: Access aur Refresh tokens generate karo [cite: 15, 16]
    access_token = create_access_token(data={"sub": user["email"]})
    refresh_token = create_refresh_token(data={"sub": user["email"]})
    
    return TokenExchangeResponse(
        access_token=access_token, 
        refresh_token=refresh_token,
        token_type="bearer" # Explicitly "bearer" return karna lazmi hai [cite: 33]
    )

@router.post("/logout", response_model=StandardActionResponse)
async def logout(request: Request, creds = Depends(security_scheme)):
    """
    The Session Revocation Step: Save token fingerprint to the fast in-memory blacklist[cite: 51, 52].
    """
    token = creds.credentials
    try:
        # Token decode karke uski expiry check karo (verification skip kar sakte hain yahan)
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get("exp", 0)
        ttl = exp - int(time.time())
        
        # Agar token valid hai, toh usay Redis mein remaining time ke liye blacklist kardo [cite: 18]
        if ttl > 0:
            redis_client = request.app.state.redis_client
            await redis_client.setex(f"blacklist:{token}", ttl, "true")
            
    except Exception:
        # Redis error ya invalid token ki surat mein server crash nahi karega
        pass 
        
    return StandardActionResponse(detail="Revocation complete")

@router.post("/refresh", response_model=TokenExchangeResponse)
async def refresh_session(request_data: TokenRefreshRequest, request: Request):
    """
    The Rotation Step: Verify refresh signature and return fresh tokens 
    without forcing re-login[cite: 49, 50].
    """
    try:
        # Refresh token ko uske apne secret se verify karo [cite: 16, 22]
        payload = jwt.decode(request_data.refresh_token, REFRESH_TOKEN_SECRET, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("token_type")
        
        # Ensure karo ke yeh galti se access token na ho [cite: 22]
        if email is None or token_type != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token usage")
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        
    # Database mein check karo user active hai ya nahi
    db_pool = request.app.state.db_pool
    user = await db_pool.fetchrow("SELECT email FROM users WHERE email = $1 AND is_active = TRUE", email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account restricted")
        
    # Naye dual tokens generate karo
    new_access_token = create_access_token(data={"sub": email})
    new_refresh_token = create_refresh_token(data={"sub": email})
    
    return TokenExchangeResponse(
        access_token=new_access_token, 
        refresh_token=new_refresh_token,
        token_type="bearer"
    )