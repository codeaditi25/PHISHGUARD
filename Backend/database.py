"""
LinkShield - Database Configuration

Purpose:
    Create and manage the database connection.

Technology:
    SQLAlchemy + SQLite
"""

from sqlalchemy import create_engine

from sqlalchemy.orm import (
    declarative_base,
    sessionmaker,
)

from config import DATABASE_URL


# =========================================================
# DATABASE ENGINE
# =========================================================

"""
The engine manages communication between Python and SQLite.

check_same_thread=False is required for SQLite when the
application may access the database from different threads.
"""

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    },
)


# =========================================================
# DATABASE SESSION
# =========================================================

"""
SessionLocal creates individual database sessions.

A session is used whenever we want to:
    - read data
    - insert data
    - update data
    - delete data
"""

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# =========================================================
# BASE MODEL
# =========================================================

"""
Every SQLAlchemy model in models.py will inherit from this
Base class.
"""

Base = declarative_base()


# =========================================================
# DATABASE SESSION DEPENDENCY
# =========================================================

def get_db():
    """
    Provide a database session to a FastAPI route.

    The session is automatically closed after the request.
    """

    db = SessionLocal()

    try:

        yield db

    finally:

        db.close()


# =========================================================
# CREATE DATABASE TABLES
# =========================================================

def create_tables():
    """
    Create all tables registered with SQLAlchemy.

    models.py must be imported before calling this function
    so SQLAlchemy knows which models exist.
    """

    Base.metadata.create_all(
        bind=engine
    )