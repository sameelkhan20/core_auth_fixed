from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from app.security import ACCESS_TOKEN_SECRET, ALGORITHM

# YAHAN CHANGE KIYA HAI: OAuth2PasswordBearer ki jagah HTTPBearer laga diya
security_scheme = HTTPBearer()

# YAHAN CHANGE KIYA HAI: 'token' parameter ki jagah 'creds' use kiya hai
async def get_current_user(request: Request, creds: HTTPAuthorizationCredentials = Depends(security_scheme)):
    # Token yahan se direct extract hoga
    token = creds.credentials
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # 1. Zero-Trust Redis Blacklist Check
    redis_client = request.app.state.redis_client
    is_blacklisted = await redis_client.get(f"blacklist:{token}")
    if is_blacklisted:
        raise credentials_exception

    # 2. Cryptographic Validation
    try:
        payload = jwt.decode(token, ACCESS_TOKEN_SECRET, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("token_type")
        
        # Ensure only access tokens are used for authentication
        if email is None or token_type != "access":
            raise credentials_exception
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise credentials_exception

    # 3. Database Validation (Non-blocking I/O)
    db_pool = request.app.state.db_pool
    user = await db_pool.fetchrow("SELECT id, email, is_active, is_superuser FROM users WHERE email = $1", email)
    
    if user is None:
        raise credentials_exception
    if not user["is_active"]:
        raise HTTPException(status_code=400, detail="Inactive user")
        
    return dict(user)