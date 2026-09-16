import os
import time
import logging
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger("mailtrace.db")

# Define SQLite database path inside backend/data/
DB_DIR = Path(__file__).resolve().parent.parent / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "mailtrace.db"

# Retrieve and normalize DATABASE_URL
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Connection args
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=False
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency for yielding database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(max_retries: int = 15, retry_delay: float = 2.0) -> bool:
    """
    Initializes database tables with graceful retry logic if the database starts slowly.
    """
    import backend.db.models  # Register models

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Connecting to database (attempt {attempt}/{max_retries})...")
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                # Ensure newly added columns exist in SQLite without requiring manual drop
                try:
                    conn.execute(text("ALTER TABLE reports ADD COLUMN ai_summary_json TEXT;"))
                    conn.commit()
                except Exception:
                    pass
            Base.metadata.create_all(bind=engine)
            logger.info("Database connection established and tables verified successfully.")
            return True
        except (OperationalError, Exception) as exc:
            if attempt >= max_retries:
                logger.error(f"Failed to connect to database after {max_retries} attempts: {exc}")
                raise
            logger.warning(
                f"Database not ready (attempt {attempt}/{max_retries}): {exc}. "
                f"Retrying in {retry_delay}s..."
            )
            time.sleep(retry_delay)
    return False


# For local SQLite development/testing, initialize tables immediately.
# For remote databases (e.g. PostgreSQL in Docker), initialization runs during application lifespan.
if "sqlite" in DATABASE_URL:
    try:
        init_db(max_retries=1, retry_delay=0.1)
    except Exception as exc:
        logger.warning(f"Initial local SQLite setup notice: {exc}")
