# Advanced Asynchronous Backend System (Enterprise Core)

## Executive Summary
[cite_start]This project is a high-performance, non-blocking asynchronous security and user routing engine[cite: 5]. [cite_start]It is designed to handle concurrent connections efficiently, implement strict cryptographic token lifecycles, and utilize in-memory layers to prevent unauthorized usage without compromising request speeds[cite: 6]. 

[cite_start]The system focuses purely on execution and runtime optimization[cite: 7]. [cite_start]The architectural scope emphasizes a Zero-Trust Network Access with a Stateless/Stateful Hybrid approach[cite: 3].

## Key Engineering Features
* [cite_start]**Asynchronous Execution Model:** Fully non-blocking I/O operations across all entry points, database reads/writes, and network caching layers[cite: 12].
* [cite_start]**Connection Lifecycle Management:** Database and fast-storage connections are managed via application start/stop lifespans, avoiding per-request connection overhead[cite: 13].
* [cite_start]**Dual-Token Cryptography:** Secure authentication leveraging short-lived Access tokens and long-lived Refresh tokens[cite: 15].
* [cite_start]**Cryptographic Separation:** Tokens are signed using completely different cryptographic secrets to prevent unauthorized extensions[cite: 16].
* [cite_start]**Stateful Token Invalidation:** Integrates a fast in-memory Redis layer to track logouts and instantly blacklist revoked tokens for their remaining lifespan[cite: 17, 18].
* [cite_start]**Zero-Trust Dependency Injection:** Automated token extraction, blacklist validation, and active database context retrieval for downstream protected routes[cite: 19].

## Technology Stack
* **Framework:** FastAPI (Python 3.12)
* **Database Engine:** PostgreSQL (Asyncpg driver)
* **In-Memory Layer:** Redis (Asyncio client)
* **Cryptography:** PyJWT (HS256 Standard), Passlib (Bcrypt)
* **CI/CD Pipeline:** GitHub Actions

## Installation & Local Setup

### 1. Prerequisites
Ensure you have Python 3.12+, PostgreSQL, and a running Redis server installed on your system.

### 2. Clone the Repository
git clone https://github.com/yourusername/core-auth-system.git
cd core-auth-system

### 3. Install Dependencies
pip install -r requirements.txt

### 4. Environment Variables
Create a strictly named `.env` file in the root directory and add your secure keys:
ACCESS_TOKEN_SECRET="your-secure-access-secret"
REFRESH_TOKEN_SECRET="your-secure-refresh-secret"

### 5. Database Initialization
Create a PostgreSQL database named `core_auth_db` and execute the following SQL schema:
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_superuser BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

### 6. Run the Server
uvicorn app.main:app --reload

## API Documentation & Verification Methods
Once the server is running, navigate to `http://127.0.0.1:8000/docs` to access the interactive Swagger UI. [cite_start]The system responses strictly adhere to predefined JSON object schemas[cite: 26]. 

### End-to-End Testing Sequence
1. [cite_start]**The Registration Step:** Submit a new email and password to receive a validated `UserRegistrationResponse`[cite: 42, 43].
2. [cite_start]**The Authentication Step:** Submit credentials to receive separate access and refresh tokens in a `TokenExchangeResponse` layout[cite: 45, 46].
3. [cite_start]**The Security Access Step:** Utilize the access token to fetch protected user profile metrics cleanly[cite: 47, 48].
4. [cite_start]**The Rotation Step:** Submit the refresh token to generate a fresh session payload securely[cite: 49, 50].
5. [cite_start]**The Session Revocation Step:** Send the active token to the logout endpoint to trigger the fast in-memory blacklist[cite: 51, 52].
6. [cite_start]**The Zero-Trust Post-Validation Step:** Attempt to reuse a blacklisted token to verify instant downstream logic protection (HTTP 401 Unauthorized)[cite: 53, 54].

## Automated Pipeline Specification
[cite_start]This repository enforces a continuous quality gate via GitHub Actions[cite: 56]. [cite_start]Code changes will not be merged into the main branch if any component fails, returns an error status code, or drops below security standards[cite: 61, 62].
* [cite_start]**Environment Spawn:** Standard runners and background dependencies (PostgreSQL, Redis) must clear health checks within 10 seconds[cite: 58].
* [cite_start]**Linter Engine:** Enforces zero syntax errors and strict adherence to PEP8 standards[cite: 58].
* [cite_start]**Static Security Audits:** Blocks builds containing hardcoded credentials or weak cryptography[cite: 58].
* [cite_start]**Asynchronous Suites:** Mandates 100% test suite completion using non-blocking network calls[cite: 58].

---
**Author:** Muhammad Zayab Ansari