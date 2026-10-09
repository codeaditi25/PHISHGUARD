"""
LinkShield - Database Models

Purpose:
    Define the structure of data stored in the database.

Current table:
    Scan

The Scan table stores the result of a URL analysis.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
)

from database import Base


# =========================================================
# SCAN MODEL
# =========================================================

class Scan(Base):
    """
    Represents one URL security scan.
    """

    __tablename__ = "scans"


    # -----------------------------------------------------
    # PRIMARY KEY
    # -----------------------------------------------------

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True,
    )


    # -----------------------------------------------------
    # SUBMITTED URL
    # -----------------------------------------------------

    url = Column(
        String(2048),
        nullable=False,
    )


    # -----------------------------------------------------
    # FINAL RISK SCORE
    # -----------------------------------------------------

    """
    Score is stored between 0 and 100.

    0:
        Lowest detected risk.

    100:
        Highest detected risk.
    """

    score = Column(
        Integer,
        nullable=False,
    )


    # -----------------------------------------------------
    # FINAL VERDICT
    # -----------------------------------------------------

    verdict = Column(
        String(50),
        nullable=False,
    )


    # -----------------------------------------------------
    # SCAN TIME
    # -----------------------------------------------------

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )