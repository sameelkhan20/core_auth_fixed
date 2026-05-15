import pytest
import pytest_asyncio
import httpx
from httpx import AsyncClient, ASGITransport

# App ko import karo
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Test env variables set karo
os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost/core_auth_db")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PORT", "6379")
os.environ.setdefault("ACCESS_TOKEN_SECRET",  "test-access-secret-for-ci-pipeline-only")
os.environ.setdefault("REFRESH_TOKEN_SECRET", "test-refresh-secret-for-ci-pipeline-only")

from app.main import app

# ── Fixtures ──────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="session")
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

TEST_EMAIL    = "testuser_ci@example.com"
TEST_PASSWORD = "StrongPass123!"

# Shared state between tests
tokens = {}


# ── Test 1: Registration ──────────────────────────────────────

@pytest.mark.asyncio
async def test_register_user(client):
    """Spec 4.1 — Registration Step"""
    response = await client.post("/users/register", json={
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    })
    # Already registered ho sakta hai CI mein — dono accept karo
    assert response.status_code in (201, 400)

    if response.status_code == 201:
        data = response.json()
        assert data["email"] == TEST_EMAIL
        assert data["is_active"] is True
        assert data["is_superuser"] is False
        assert "id" in data
        assert "created_at" in data
        assert "password" not in data          # Password kabhi return nahi hona chahiye
        assert "hashed_password" not in data


# ── Test 2: Duplicate Email Blocked ──────────────────────────

@pytest.mark.asyncio
async def test_register_duplicate_email(client):
    """Same email dobara register nahi honi chahiye"""
    # Pehle register karo
    await client.post("/users/register", json={
        "email": "duplicate_ci@example.com",
        "password": TEST_PASSWORD
    })
    # Dobara same email
    response = await client.post("/users/register", json={
        "email": "duplicate_ci@example.com",
        "password": TEST_PASSWORD
    })
    assert response.status_code == 400


# ── Test 3: Login ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login(client):
    """Spec 4.2 — Authentication Step"""
    # Pehle register karo agar nahi hai
    await client.post("/users/register", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })

    response = await client.post("/auth/login", json={
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    })
    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["access_token"] != data["refresh_token"]  # Dono alag hone chahiye

    # Tokens save karo agle tests ke liye
    tokens["access"]  = data["access_token"]
    tokens["refresh"] = data["refresh_token"]


# ── Test 4: Wrong Password Blocked ───────────────────────────

@pytest.mark.asyncio
async def test_login_wrong_password(client):
    """Galat password se login nahi hona chahiye"""
    response = await client.post("/auth/login", json={
        "email": TEST_EMAIL,
        "password": "WrongPassword999!"
    })
    assert response.status_code == 401


# ── Test 5: Protected Route /me ───────────────────────────────

@pytest.mark.asyncio
async def test_get_me(client):
    """Spec 4.3 — Security Access Step"""
    assert "access" in tokens, "Login test pehle run karo"

    response = await client.get("/users/me", headers={
        "Authorization": f"Bearer {tokens['access']}"
    })
    assert response.status_code == 200

    data = response.json()
    assert data["email"] == TEST_EMAIL


# ── Test 6: /me Without Token ────────────────────────────────

@pytest.mark.asyncio
async def test_get_me_no_token(client):
    """Token ke bina protected route accessible nahi honi chahiye"""
    response = await client.get("/users/me")
    assert response.status_code == 401


# ── Test 7: Token Refresh ─────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_token(client):
    """Spec 4.4 — The Rotation Step"""
    assert "refresh" in tokens, "Login test pehle run karo"

    response = await client.post("/auth/refresh", headers={
        "Authorization": f"Bearer {tokens['refresh']}"
    })
    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

    # Naye tokens save karo
    tokens["access"]  = data["access_token"]
    tokens["refresh"] = data["refresh_token"]


# ── Test 8: Access Token as Refresh — Blocked ────────────────

@pytest.mark.asyncio
async def test_access_token_cannot_refresh(client):
    """Access token ko refresh endpoint pe use nahi kar sakte"""
    assert "access" in tokens, "Login test pehle run karo"

    response = await client.post("/auth/refresh", headers={
        "Authorization": f"Bearer {tokens['access']}"
    })
    assert response.status_code == 401


# ── Test 9: Logout ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logout(client):
    """Spec 4.5 — Session Revocation Step"""
    assert "access" in tokens, "Login test pehle run karo"

    response = await client.post("/auth/logout", headers={
        "Authorization": f"Bearer {tokens['access']}"
    })
    assert response.status_code == 200
    assert response.json()["detail"] == "Revocation complete"

    # Blacklisted token save karo
    tokens["blacklisted"] = tokens["access"]


# ── Test 10: Zero-Trust — Blacklisted Token Blocked ──────────

@pytest.mark.asyncio
async def test_blacklisted_token_rejected(client):
    """Spec 4.6 — Zero-Trust Post-Validation Step"""
    assert "blacklisted" in tokens, "Logout test pehle run karo"

    response = await client.get("/users/me", headers={
        "Authorization": f"Bearer {tokens['blacklisted']}"
    })
    # Blacklisted token se 401 aana chahiye
    assert response.status_code == 401
