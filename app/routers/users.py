from fastapi import APIRouter, Depends, HTTPException, status, Request
from app.schemas import UserRegistrationResponse, UserCreate
from app.security import get_password_hash
from app.dependencies import get_current_user

router = APIRouter(prefix="/users", tags=["Users"])


@router.post("/register", response_model=UserRegistrationResponse, status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate, request: Request):
    """
    Naya user register karo.
    Spec Section 4.1 — The Registration Step.
    """
    db_pool = request.app.state.db_pool

    # Email already exist karta hai?
    existing_user = await db_pool.fetchrow(
        "SELECT id FROM users WHERE email = $1", user.email
    )
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Password hash karo — plaintext kabhi save nahi hoga
    hashed_pwd = get_password_hash(user.password)

    insert_query = """
        INSERT INTO users (email, hashed_password)
        VALUES ($1, $2)
        RETURNING id, email, is_active, is_superuser, created_at
    """
    try:
        new_user_record = await db_pool.fetchrow(insert_query, user.email, hashed_pwd)
    except Exception:
        raise HTTPException(status_code=500, detail="Database operation failed")

    return UserRegistrationResponse(**dict(new_user_record))


@router.get("/me", response_model=UserRegistrationResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """
    Apna profile dekho — sirf valid token wale access kar sakte hain.
    Spec Section 4.3 — The Security Access Step.
    Zero-Trust: dependencies.py mein token + blacklist check ho chuka hai.
    """
    return UserRegistrationResponse(**current_user)
