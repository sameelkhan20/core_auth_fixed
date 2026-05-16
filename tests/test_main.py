import pytest
import pytest_asyncio
import os

# Env variables — import se PEHLE
os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost/core_auth_db")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PORT", "6379")
os.environ.setdefault("ACCESS_TOKEN_SECRET", "test-access-secret-for-ci-pipeline-only")
os.environ.setdefault("REFRESH_TOKEN_SECRET", "test-refresh-secret-for-ci-pipeline-only")

from httpx import AsyncClient, ASGITransport
from app.main import app

TEST_EMAIL = "testuser_ci@example.com"
TEST_PASSWORD = "StrongPass123!"
tokens = {}


# ── Fixture — lifespan manually trigger karo ─────────────────────────────────

@pytest_asyncio.fixture()
async def client():
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test"
        ) as ac:
            yield ac


# ── Test 1 ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_user(client):
    """Spec 4.1 — Registration Step"""
    response = await client.post("/users/register", json={
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    })
    assert response.status_code in (201, 400)
    if response.status_code == 201:
        data = response.json()
        assert data["email"] == TEST_EMAIL
        assert data["is_active"] is True
        assert data["is_superuser"] is False
        assert "id" in data
        assert "created_at" in data
        assert "password" not in data
        assert "hashed_password" not in data


# ── Test 2 ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_duplicate_email(client):
    """Same email dobara register nahi honi chahiye"""
    await client.post("/users/register", json={
        "email": "duplicate_ci@example.com",
        "password": TEST_PASSWORD
    })
    response = await client.post("/users/register", json={
        "email": "duplicate_ci@example.com",
        "password": TEST_PASSWORD
    })
    assert response.status_code == 400


# ── Test 3 ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login(client):
    """Spec 4.2 — Authentication Step"""
    await client.post("/users/register", json={
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
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
    assert data["access_token"] != data["refresh_token"]
    tokens["access"] = data["access_token"]
    tokens["refresh"] = data["refresh_token"]


# ── Test 4 ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_wrong_password(client):
    """Galat password se login nahi hona chahiye"""
    response = await client.post("/auth/login", json={
        "email": TEST_EMAIL,
        "password": "WrongPassword999!"
    })
    assert response.status_code == 401


# ── Test 5 ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_me(client):
    """Spec 4.3 — Security Access Step"""
    await client.post("/users/register", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })
    login_res = await client.post("/auth/login", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })
    access_token = login_res.json()["access_token"]

    response = await client.get("/users/me", headers={
        "Authorization": f"Bearer {access_token}"
    })
    assert response.status_code == 200
    assert response.json()["email"] == TEST_EMAIL


# ── Test 6 ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_me_no_token(client):
    """Token ke bina protected route accessible nahi honi chahiye"""
    response = await client.get("/users/me")
    assert response.status_code == 401


# ── Test 7 ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_token(client):
    """Spec 4.4 — The Rotation Step"""
    await client.post("/users/register", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })
    login_res = await client.post("/auth/login", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })
    refresh_token = login_res.json()["refresh_token"]

    response = await client.post("/auth/refresh", json={
        "refresh_token": refresh_token
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


# ── Test 8 ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_access_token_cannot_refresh(client):
    """Access token ko refresh endpoint pe use nahi kar sakte"""
    await client.post("/users/register", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })
    login_res = await client.post("/auth/login", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })
    access_token = login_res.json()["access_token"]

    response = await client.post("/auth/refresh", json={
        "refresh_token": access_token
    })
    assert response.status_code == 401


# ── Test 9 ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logout(client):
    """Spec 4.5 — Session Revocation Step"""
    await client.post("/users/register", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })
    login_res = await client.post("/auth/login", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })
    access_token = login_res.json()["access_token"]

    response = await client.post("/auth/logout", headers={
        "Authorization": f"Bearer {access_token}"
    })
    assert response.status_code == 200
    assert response.json()["detail"] == "Revocation complete"
    tokens["blacklisted"] = access_token


# ── Test 10 ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_blacklisted_token_rejected(client):
    """Spec 4.6 — Zero-Trust Post-Validation Step"""
    await client.post("/users/register", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })
    login_res = await client.post("/auth/login", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD
    })
    access_token = login_res.json()["access_token"]

    await client.post("/auth/logout", headers={
        "Authorization": f"Bearer {access_token}"
    })

    response = await client.get("/users/me", headers={
        "Authorization": f"Bearer {access_token}"
    })
    assert response.status_code == 401