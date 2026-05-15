from fastapi import APIRouter, Depends, HTTPException, status, Request
import time
import jwt
from pydantic import BaseModel
from app.schemas import TokenExchangeResponse, StandardActionResponse, UserLogin

# YAHAN CHANGE KIYA: REFRESH_TOKEN_SECRET aur ALGORITHM ko import kiya
from app.security import verify_password, create_access_token, create_refresh_token, REFRESH_TOKEN_SECRET, ALGORITHM
from app.dependencies import security_scheme

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Refresh endpoint ke liye ek chota sa input schema
class TokenRefreshRequest(BaseModel):
    refresh_token: str

@router.post("/login", response_model=TokenExchangeResponse)
async def login(user_data: UserLogin, request: Request):
    db_pool = request.app.state.db_pool
    
    user = await db_pool.fetchrow("SELECT * FROM users WHERE email = $1", user_data.email)
    if not user or not verify_password(user_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
        
    access_token = create_access_token(data={"sub": user["email"]})
    refresh_token = create_refresh_token(data={"sub": user["email"]})
    
    return TokenExchangeResponse(access_token=access_token, refresh_token=refresh_token)

@router.post("/logout", response_model=StandardActionResponse)
async def logout(request: Request, creds = Depends(security_scheme)):
    token = creds.credentials
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get("exp", 0)
        ttl = exp - int(time.time())
        
        if ttl > 0:
            redis_client = request.app.state.redis_client
            await redis_client.setex(f"blacklist:{token}", ttl, "true")
    except Exception:
        pass 
        
    return StandardActionResponse(detail="Revocation complete")

# --- YAHAN NAYA REFRESH ENDPOINT ADD KIYA HAI ---
@router.post("/refresh", response_model=TokenExchangeResponse)
async def refresh_session(request_data: TokenRefreshRequest, request: Request):
    """
    The Rotation Step: Verifies the refresh signature and returns a fresh TokenExchangeResponse.
    """
    try:
        # Strict validation with REFRESH_TOKEN_SECRET
        payload = jwt.decode(request_data.refresh_token, REFRESH_TOKEN_SECRET, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("token_type")
        
        # Ensure only refresh tokens can be used here
        if email is None or token_type != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token signature")
        
    # Database check (Non-blocking I/O)
    db_pool = request.app.state.db_pool
    user = await db_pool.fetchrow("SELECT email FROM users WHERE email = $1 AND is_active = TRUE", email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive or not found")
        
    # Generate fresh tokens
    new_access_token = create_access_token(data={"sub": email})
    new_refresh_token = create_refresh_token(data={"sub": email})
    
    return TokenExchangeResponse(access_token=new_access_token, refresh_token=new_refresh_token)