# Advanced Asynchronous Backend System (Enterprise Core)

![Version](https://img.shields.io/badge/Version-1.4.2--Prod-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12%2B-brightgreen.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-Async-009688.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Asyncpg-336791.svg)
![Redis](https://img.shields.io/badge/Redis-In--Memory-DC382D.svg)

## 🚀 Executive Summary
This repository contains a high-performance, non-blocking asynchronous security and user routing engine. Built purely for runtime execution and optimization, the system handles concurrent connections efficiently, enforces strict cryptographic token lifecycles, and implements a fast in-memory layer to block unauthorized usage with zero latency overhead. 

The architecture strictly adheres to a **Zero-Trust Network Access** model utilizing a **Stateless/Stateful Hybrid** approach.

## ⚙️ Core Engineering Features

### 1. Asynchronous Execution Model
* **Non-Blocking I/O:** All entry points, database transactions, and network caching layers operate on a single-thread loop worker model using asynchronous libraries.
* **Pool Lifecycle Management:** Database engines and fast-storage systems initialize connection pools strictly tied to the application's startup and shutdown events, eliminating per-request connection bottlenecks.

### 2. High-Security Cryptography & Authentication
* **Dual-Token Key Separation:** Implements distinct `Access` (short-lived) and `Refresh` (long-lived) tokens, mathematically signed with completely isolated cryptographic secrets via standard HS256 algorithms.
* **Stateful Token Invalidation:** Integrates Redis as an ultra-fast in-memory layer to track session logouts. Revoked tokens are instantly blacklisted for their remaining valid lifespan.
* **Zero-Trust Dependency Injection:** Downstream routes utilize a secure injection system that autonomously extracts tokens, verifies algorithmic signatures, checks the Redis blacklist, and injects the validated user context.

## 🛠️ Technology Stack
* **Core Framework:** FastAPI
* **Database & ORM:** PostgreSQL, `asyncpg`
* **Caching & Blacklisting:** Redis, `redis.asyncio`
* **Security:** `PyJWT` (Tokens), `passlib[bcrypt]` (Password Hashing)
* **Testing & CI/CD:** `pytest-asyncio`, `httpx`, GitHub Actions

## 💻 Local Installation & Setup

### Prerequisites
* Python 3.12+
* PostgreSQL server running locally
* Redis server running locally

### 1. Clone & Install
```bash
git clone [https://github.com/yourusername/core-auth-system.git](https://github.com/yourusername/core-auth-system.git)
cd core-auth-system
pip install -r requirements.txt
2. Environment Configuration
Create a .env file in the root directory containing your secure cryptographic keys:

Code snippet
ACCESS_TOKEN_SECRET="your-super-secure-access-key-here"
REFRESH_TOKEN_SECRET="your-super-secure-refresh-key-here"
3. Database Initialization
Create a PostgreSQL database named core_auth_db and apply the core schema:

SQL
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_superuser BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
4. Run the Engine
Bash
uvicorn app.main:app --reload
🧪 Testing Blueprint & Verification
The system provides fully interactive API documentation at http://127.0.0.1:8000/docs. To verify the core engine, execute the following end-to-end sequence:

Registration: Submit credentials to /users/register to receive a highly structured UserRegistrationResponse.

Authentication: Submit credentials to /auth/login to obtain dual-signed tokens (TokenExchangeResponse).

Security Access: Authorize the Swagger UI using the access token and cleanly fetch protected metrics from /users/me.

Token Rotation: Submit the refresh token to /auth/refresh to securely generate a new token pair without re-authenticating.

Session Revocation: Hit the /auth/logout endpoint to instantly write the active access token's fingerprint to the Redis blacklist.

Zero-Trust Post-Validation: Re-attempt the /users/me endpoint with the blacklisted token to confirm an instant HTTP 401 Unauthorized block.

🛡️ CI/CD Pipeline Specification
Code integrity is enforced via a strict GitHub Actions automated pipeline. Commits cannot be merged if they fail any of the following quality gates:

Environment Spawn: Parallel instantiation of isolated Postgres and Redis containers passing sub-10-second health checks.

Linter Engine: Strict PEP8 compliance checks via flake8 with zero syntax errors permitted.

Static Security Audits: Deep repository scans using bandit (SAST) blocking any hardcoded credentials or weak cryptographic bindings.

Asynchronous Suites: 100% test pass rate via pytest executing entirely non-blocking integration tests across all lifecycle events.