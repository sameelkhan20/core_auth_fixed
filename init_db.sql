-- PostgreSQL mein ye query run karo pehli baar
-- Command: psql -U postgres -d core_auth_db -f init_db.sql

CREATE TABLE IF NOT EXISTS users (
    id               SERIAL PRIMARY KEY,
    email            VARCHAR(255) UNIQUE NOT NULL,
    hashed_password  VARCHAR(255) NOT NULL,
    is_active        BOOLEAN DEFAULT TRUE,
    is_superuser     BOOLEAN DEFAULT FALSE,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);
