"""
LinkShield - Configuration

Purpose:
    Keep backend settings in one place.

    This prevents configuration values from being scattered
    throughout the project.
"""

from pathlib import Path


# =========================================================
# PROJECT PATHS
# =========================================================

# Directory containing this file.
BASE_DIR = Path(__file__).resolve().parent


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

# SQLite is suitable for the current development/demo version.
# Later, this can be changed to PostgreSQL or another database.
DATABASE_URL = f"sqlite:///{BASE_DIR / 'linkshield.db'}"


# =========================================================
# API CONFIGURATION
# =========================================================

APP_NAME = "LinkShield API"

APP_VERSION = "1.0.0"

HOST = "127.0.0.1"

PORT = 8000


# =========================================================
# CORS CONFIGURATION
# =========================================================

# Development configuration.
#
# In production, replace "*" with the actual frontend domain.
CORS_ORIGINS = [
    "*"
]