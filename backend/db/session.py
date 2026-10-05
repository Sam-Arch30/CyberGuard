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

engine_kwargs = {
    "pool_pre_ping": True,
    "echo": False,
}

if "sqlite" in DATABASE_URL:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # Production PostgreSQL connection pool optimization
    engine_kwargs["pool_size"] = int(os.getenv("DB_POOL_SIZE", "10"))
    engine_kwargs["max_overflow"] = int(os.getenv("DB_MAX_OVERFLOW", "20"))
    engine_kwargs["pool_recycle"] = int(os.getenv("DB_POOL_RECYCLE", "1800"))

engine = create_engine(DATABASE_URL, **engine_kwargs)
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
                column_migrations = [
                    "ALTER TABLE reports ADD COLUMN ai_summary_json TEXT;",
                    "ALTER TABLE entities ADD COLUMN canonical_key VARCHAR(500);",
                    "ALTER TABLE entities ADD COLUMN workspace_id VARCHAR(100);",
                    "ALTER TABLE relationships ADD COLUMN origin VARCHAR(50) DEFAULT 'OBSERVED';",
                    "ALTER TABLE relationships ADD COLUMN status VARCHAR(30) DEFAULT 'ACTIVE';",
                    "ALTER TABLE relationships ADD COLUMN workspace_id VARCHAR(100);",
                    "ALTER TABLE incidents ADD COLUMN workspace_id VARCHAR(64) DEFAULT 'default';",
                    "ALTER TABLE campaigns ADD COLUMN status VARCHAR(30) DEFAULT 'CANDIDATE';",
                    "ALTER TABLE campaigns ADD COLUMN workspace_id VARCHAR(64) DEFAULT 'default';",
                    "ALTER TABLE campaigns ADD COLUMN engine_version VARCHAR(32) DEFAULT '2.0.0';",
                    "ALTER TABLE campaigns ADD COLUMN supporting_evidence_json TEXT DEFAULT '[]';",
                    "ALTER TABLE campaigns ADD COLUMN contradicting_evidence_json TEXT DEFAULT '[]';",
                    "ALTER TABLE campaigns ADD COLUMN correlation_summary TEXT;",
                ]
                for stmt in column_migrations:
                    try:
                        conn.execute(text(stmt))
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
