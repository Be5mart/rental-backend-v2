# backend/config/database.py
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base

def _normalize_db_url(url: str) -> str:
    # Accept plain postgres or SQLAlchemy dsn; coerce to psycopg2 driver
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)

    # Add SSL for common hosted DBs if missing
    needs_ssl = ("railway.app" in url or "amazonaws.com" in url or "render.com" in url or "gcp" in url)
    if needs_ssl and "sslmode=" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=require"
    return url

DB_URL = os.getenv("DATABASE_URL")
if not DB_URL:
    # Safe local fallback so dev boots without Postgres
    DB_URL = "sqlite:///instance/local.db"

DB_URL = _normalize_db_url(DB_URL)

engine = create_engine(DB_URL, pool_pre_ping=True, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True))
Base = declarative_base()

def healthcheck():
    # Optional: quick sanity ping
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
