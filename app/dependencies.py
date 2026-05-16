from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from app.security import ACCESS_TOKEN_SECRET, ALGORITHM

# 1. HTTPBearer Swagger UI mein direct token paste karne wala box layega
security_scheme = HTTPBearer()


async def get_current_user(
        request: Request, creds: HTTPAuthorizationCredentials = Depends(security_scheme)):
    # Token ab direct credentials object se extract hoga
    token = creds.credentials

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 2. Zero-Trust Redis Blacklist Check
    try:
        redis_client = request.app.state.redis_client
        is_blacklisted = await redis_client.get(f"blacklist:{token}")
        if is_blacklisted:
            raise credentials_exception
    except HTTPException:
        raise
    except Exception:
        # Redis down hai — warning log karo lekin crash mat karo
        # Production mein Redis lazmi chalna chahiye!
        import warnings
        warnings.warn(
            "Redis not available — blacklist check skipped!",
            RuntimeWarning)

    # 3. Cryptographic Validation
    try:
        payload = jwt.decode(
            token,
            ACCESS_TOKEN_SECRET,
            algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("token_type")

        # Ensure only access tokens are used for authentication (Refresh token
        # block ho jayega yahan)
        if email is None or token_type != "access":
            raise credentials_exception
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired")
    except jwt.InvalidTokenError:
        raise credentials_exception

    # 4. Database Validation (Non-blocking I/O)
    db_pool = request.app.state.db_pool
    # YAHAN CHANGE KIYA HAI: Query mein 'created_at' ka izafa kar diya
    user = await db_pool.fetchrow("SELECT id, email, is_active, is_superuser, created_at FROM users WHERE email = $1", email)

    if user is None:
        raise credentials_exception
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user")

    return dict(user)
