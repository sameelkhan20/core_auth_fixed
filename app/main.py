from fastapi import FastAPI
from contextlib import asynccontextmanager
import asyncpg
import redis.asyncio as redis
import os
from dotenv import load_dotenv

# Import your routers
from app.routers import users, auth

load_dotenv()
@asynccontextmanager
async def lifespan(app: FastAPI):
    # App state variables for non-blocking pooled resources
    # Credentials .env file se aa rahe hain — hardcoded nahi
    database_url = os.getenv("DATABASE_URL")
    redis_host   = os.getenv("REDIS_HOST", "localhost")
    redis_port   = int(os.getenv("REDIS_PORT", 6379))

    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable not set!")

    app.state.db_pool = await asyncpg.create_pool(dsn=database_url)
    app.state.redis_client = redis.Redis(
        host=redis_host,
        port=redis_port,
        decode_responses=True
    )

    print("System resources initialized successfully.")

    yield

    await app.state.db_pool.close()
    await app.state.redis_client.close()
    print("System resources cleaned up.")

app = FastAPI(lifespan=lifespan, title="Advanced Asynchronous Backend System")

# Attach the routers
app.include_router(users.router)
app.include_router(auth.router)

@app.get("/")
async def root():
    return {"status": "Engine Running"}
