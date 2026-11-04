"""Pooled engine and request-scoped SQLAlchemy sessions."""

from __future__ import annotations

from collections.abc import Generator
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from api.core.config import Settings


def build_engine(settings: Settings) -> Engine:
    if not settings.database_url:
        raise RuntimeError("NII_DATABASE_URL is not configured.")
    options = {"pool_pre_ping": True}
    if settings.database_url.startswith("sqlite:"):
        options.update({"connect_args": {"check_same_thread": False}, "pool_pre_ping": False})
    return create_engine(settings.database_url, **options)


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def session_scope(factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    session = factory()
    try:
        yield session
    finally:
        session.close()
