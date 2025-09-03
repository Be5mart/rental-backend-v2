import os
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    # Use Railway DATABASE_URL if present; fallback to local SQLite for dev
    db_url = os.getenv("DATABASE_URL", "sqlite:///local.db")
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", db_url)
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    # Helps avoid stale connections in managed DBs
    app.config.setdefault("SQLALCHEMY_ENGINE_OPTIONS", {"pool_pre_ping": True})
    db.init_app(app)
