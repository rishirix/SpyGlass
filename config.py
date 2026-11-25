"""Central configuration for Spyglass.

All settings come from environment variables (loaded from .env).
No AWS credentials are ever stored here.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _int_env(name: str, default: int) -> int:
    """Read an integer env var, falling back to the default if invalid."""
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


# "demo" (moto emulator) or "live" (real AWS)
MODE = os.getenv("SPYGLASS_MODE", "demo").strip().lower()
if MODE not in ("demo", "live"):
    MODE = "demo"

REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
AWS_PROFILE = os.getenv("AWS_PROFILE") or None
MOTO_ENDPOINT = os.getenv("MOTO_ENDPOINT", "http://127.0.0.1:5001")

# Policy threshold, configurable per organisation
ACCESS_KEY_MAX_AGE_DAYS = _int_env("ACCESS_KEY_MAX_AGE_DAYS", 90)

# Severity weights used by the risk score (Step 10)
SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")
DB_PATH = BASE_DIR / "data" / "spyglass.db"
REPORTS_DIR = BASE_DIR / "reports"
