from __future__ import annotations

import os
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base


def _normalize_db_url(url: str) -> str:
    """
    Normalize DATABASE_URL for SQLAlchemy + psycopg2 and add SSL for hosted DBs.

    - Convert:
        postgres://...     -> postgresql+psycopg2://...
        postgresql://...   -> postgresql+psycopg2://...
    - For common hosted providers, append sslmode=require if not present.
    - Leave sqlite:/// URLs untouched.
    """
    if not url:
        return url

    # Keep SQLite as-is
    if url.startswith("sqlite:///"):
        return url

    # Ensure psycopg2 driver is specified
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)

    # For hosted Postgres, set sslmode=require if missing
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    hosted_domains = (
        "railway.app",
        "amazonaws.com",    # RDS
        "render.com",
        "gcp",              # generic GCP hostnames
        "azure.com",
        "supabase.co",
        "neon.tech",
        "heroku.com",
        "herokuapp.com",
    )

    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if any(d in host for d in hosted_domains) and "sslmode" not in query:
        query["sslmode"] = "require"
        url = urlunparse(parsed._replace(query=urlencode(query)))

    return url


# Read env with safe local fallback
DB_URL = os.getenv("DATABASE_URL")
if not DB_URL:
    # Local dev fallback (no Postgres required)
    DB_URL = "sqlite:///instance/local.db"

DB_URL = _normalize_db_url(DB_URL)

# If using SQLite locally, ensure the folder exists (no-op in prod)
if DB_URL.startswith("sqlite:///"):
    os.makedirs("instance", exist_ok=True)

# Create engine/session factory (no DB I/O at import time)
engine = create_engine(DB_URL, pool_pre_ping=True, future=True)
SessionLocal = scoped_session(
    sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
)
Base = declarative_base()


def healthcheck() -> None:
    """
    Lightweight DB ping; safe to call from a debug route or one-off task.
    """
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
