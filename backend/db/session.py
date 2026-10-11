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
                    "ALTER TABLE threat_events ADD COLUMN risk_assessment_id VARCHAR(64);",
                    "ALTER TABLE attack_paths ADD COLUMN workspace_id VARCHAR(64) DEFAULT 'default';",
                    "ALTER TABLE reports ADD COLUMN investigation_id VARCHAR(128);",
                    "ALTER TABLE reports ADD COLUMN report_type VARCHAR(30) DEFAULT 'ANALYST';",
                    "ALTER TABLE reports ADD COLUMN status VARCHAR(30) DEFAULT 'READY';",
                    "ALTER TABLE reports ADD COLUMN report_version INTEGER DEFAULT 1;",
                    "ALTER TABLE reports ADD COLUMN classification VARCHAR(30) DEFAULT 'CONFIDENTIAL';",
                    "ALTER TABLE reports ADD COLUMN redaction_level VARCHAR(30) DEFAULT 'NONE';",
                    "ALTER TABLE reports ADD COLUMN confidence FLOAT DEFAULT 1.0;",
                    "ALTER TABLE reports ADD COLUMN content_options_json TEXT DEFAULT '{}';",
                    "ALTER TABLE reports ADD COLUMN snapshot_data_json TEXT DEFAULT '{}';",
                    "ALTER TABLE reports ADD COLUMN quality_check_json TEXT DEFAULT '{}';",
                    "ALTER TABLE reports ADD COLUMN superseded_by VARCHAR(36);",
                    "ALTER TABLE reports ADD COLUMN workspace_id VARCHAR(128) DEFAULT 'default';",
                    "ALTER TABLE analysis_events ADD COLUMN sequence INTEGER DEFAULT 1;",
                    "ALTER TABLE background_job_events ADD COLUMN sequence INTEGER DEFAULT 1;",
                    "ALTER TABLE notifications ADD COLUMN assigned_to VARCHAR(100);",
                    "ALTER TABLE notifications ADD COLUMN resolved_at DATETIME;",
                    "ALTER TABLE notifications ADD COLUMN resolved_by VARCHAR(100);",
                    "ALTER TABLE notifications ADD COLUMN resolution_reason TEXT;",
                    "ALTER TABLE notifications ADD COLUMN false_positive_reason TEXT;",
                    "ALTER TABLE notifications ADD COLUMN suppression_reason TEXT;",
                    "ALTER TABLE notifications ADD COLUMN suppression_scope VARCHAR(50);",
                    "ALTER TABLE notifications ADD COLUMN updated_at DATETIME;",
                    "ALTER TABLE incidents ADD COLUMN priority VARCHAR(20) DEFAULT 'P3_MEDIUM';",
                    "ALTER TABLE incidents ADD COLUMN category VARCHAR(50) DEFAULT 'OTHER';",
                    "ALTER TABLE incidents ADD COLUMN first_seen_at DATETIME;",
                    "ALTER TABLE incidents ADD COLUMN last_seen_at DATETIME;",
                    "ALTER TABLE incidents ADD COLUMN acknowledged_at DATETIME;",
                    "ALTER TABLE incidents ADD COLUMN contained_at DATETIME;",
                    "ALTER TABLE incidents ADD COLUMN resolved_at DATETIME;",
                    "ALTER TABLE incidents ADD COLUMN team_id VARCHAR(64);",
                    "ALTER TABLE incidents ADD COLUMN primary_alert_id VARCHAR(36);",
                    "ALTER TABLE incidents ADD COLUMN primary_cluster_id VARCHAR(36);",
                    "ALTER TABLE incidents ADD COLUMN investigation_id VARCHAR(128);",
                    "ALTER TABLE incidents ADD COLUMN report_id VARCHAR(36);",
                    "ALTER TABLE incidents ADD COLUMN created_by VARCHAR(100);",
                    "ALTER TABLE incidents ADD COLUMN resolved_by VARCHAR(100);",
                    "ALTER TABLE incidents ADD COLUMN resolution_reason TEXT;",
                    "ALTER TABLE incidents ADD COLUMN duplicate_of_id VARCHAR(36);",
                    "ALTER TABLE incidents ADD COLUMN sla_policy_id VARCHAR(36);",
                    "ALTER TABLE incidents ADD COLUMN escalation_level INTEGER DEFAULT 0;",
                    "ALTER TABLE incidents ADD COLUMN sla_status VARCHAR(30) DEFAULT 'HEALTHY';",
                    "ALTER TABLE incidents ADD COLUMN next_sla_deadline DATETIME;",
                    "ALTER TABLE candidate_rules ADD COLUMN rule_identifier VARCHAR(64);",
                    "ALTER TABLE candidate_rules ADD COLUMN owner_id VARCHAR(100) DEFAULT 'analyst';",
                    "ALTER TABLE candidate_rules ADD COLUMN team_id VARCHAR(100);",
                    "ALTER TABLE candidate_rules ADD COLUMN last_editor_id VARCHAR(100);",
                    "ALTER TABLE candidate_rules ADD COLUMN deployment_state VARCHAR(30) DEFAULT 'DRAFT';",
                    "ALTER TABLE candidate_rules ADD COLUMN operational_health VARCHAR(30) DEFAULT 'HEALTHY';",
                    "ALTER TABLE candidate_rules ADD COLUMN health_reason VARCHAR(500);",
                    "ALTER TABLE candidate_rules ADD COLUMN health_updated_at DATETIME;",
                    "ALTER TABLE candidate_rules ADD COLUMN review_interval_days INTEGER DEFAULT 90;",
                    "ALTER TABLE candidate_rules ADD COLUMN next_review_due DATETIME;",
                    "ALTER TABLE candidate_rules ADD COLUMN last_reviewed_at DATETIME;",
                    "ALTER TABLE candidate_rules ADD COLUMN dependencies_json TEXT DEFAULT '[]';",
                    "ALTER TABLE candidate_rules ADD COLUMN collections_json TEXT DEFAULT '[]';",
                    "ALTER TABLE candidate_rules ADD COLUMN replaced_by_rule_id VARCHAR(36);",
                    "ALTER TABLE candidate_rules ADD COLUMN last_matched_at DATETIME;",
                    "ALTER TABLE candidate_rules ADD COLUMN total_match_count INTEGER DEFAULT 0;",
                    "ALTER TABLE candidate_rule_executions ADD COLUMN disposition VARCHAR(30);",
                    "ALTER TABLE candidate_rule_executions ADD COLUMN disposition_by VARCHAR(100);",
                    "ALTER TABLE candidate_rule_executions ADD COLUMN disposition_at DATETIME;",
                    "ALTER TABLE candidate_rule_executions ADD COLUMN disposition_notes VARCHAR(500);",
                    "ALTER TABLE candidate_rule_executions ADD COLUMN suppression_applied_id VARCHAR(36);",
                    "ALTER TABLE candidate_rule_executions ADD COLUMN match_explanation_json TEXT DEFAULT '{}';",
                    "ALTER TABLE candidate_rule_executions ADD COLUMN detection_id VARCHAR(64);",
                    "ALTER TABLE candidate_rule_executions ADD COLUMN finding_id VARCHAR(36);",
                    "ALTER TABLE candidate_rules ADD COLUMN category VARCHAR(50) DEFAULT 'PHISHING';",
                    "ALTER TABLE candidate_rules ADD COLUMN provenance_type VARCHAR(50) DEFAULT 'ANALYST_CREATED';",
                    "ALTER TABLE candidate_rules ADD COLUMN provenance_id VARCHAR(128);",
                    "ALTER TABLE candidate_rules ADD COLUMN provenance_details_json TEXT DEFAULT '{}';",
                    "ALTER TABLE candidate_rules ADD COLUMN data_sources_json TEXT DEFAULT '[]';",
                    "ALTER TABLE candidate_rules ADD COLUMN cost_class VARCHAR(20) DEFAULT 'LOW';",
                    "ALTER TABLE candidate_rules ADD COLUMN tags_json TEXT DEFAULT '[]';",
                    "ALTER TABLE candidate_rules ADD COLUMN attack_techniques_json TEXT DEFAULT '[]';",
                    "ALTER TABLE candidate_rules ADD COLUMN is_system_rule BOOLEAN DEFAULT 0;",
                    "ALTER TABLE candidate_rules ADD COLUMN disabled_at DATETIME;",
                    "ALTER TABLE candidate_rule_versions ADD COLUMN data_sources_json TEXT DEFAULT '[]';",
                    "ALTER TABLE candidate_rule_versions ADD COLUMN diff_summary_json TEXT DEFAULT '{}';",
                    "ALTER TABLE candidate_rule_versions ADD COLUMN cost_class VARCHAR(20) DEFAULT 'LOW';",
                    "ALTER TABLE candidate_rules ADD COLUMN last_validation_run_id VARCHAR(36);",
                    "ALTER TABLE candidate_rules ADD COLUMN validation_status VARCHAR(30) DEFAULT 'NOT_RUN';",
                    "ALTER TABLE candidate_rules ADD COLUMN validation_updated_at DATETIME;",
                    "ALTER TABLE behavioral_deviations ADD COLUMN finding_id VARCHAR(36);",
                    "ALTER TABLE behavioral_deviations ADD COLUMN alert_id VARCHAR(36);",
                    "ALTER TABLE findings ADD COLUMN is_composite BOOLEAN DEFAULT 0;",
                    "ALTER TABLE findings ADD COLUMN parent_finding_id VARCHAR(36);",
                    "ALTER TABLE findings ADD COLUMN correlation_id VARCHAR(36);",
                    "ALTER TABLE campaigns ADD COLUMN threat_actor_id VARCHAR(36);",
                    "ALTER TABLE campaigns ADD COLUMN attribution_state VARCHAR(30) DEFAULT 'UNKNOWN';",
                    "ALTER TABLE campaigns ADD COLUMN attribution_confidence FLOAT DEFAULT 0.0;",
                    "ALTER TABLE campaigns ADD COLUMN lifecycle_status VARCHAR(30) DEFAULT 'CANDIDATE';",
                    "ALTER TABLE campaigns ADD COLUMN activity_state VARCHAR(30) DEFAULT 'ACTIVE';",
                    "ALTER TABLE campaigns ADD COLUMN watch_state VARCHAR(30) DEFAULT 'NOT_MONITORED';",
                    "ALTER TABLE campaigns ADD COLUMN description TEXT;",
                    "ALTER TABLE campaigns ADD COLUMN mitre_techniques_json TEXT DEFAULT '[]';",
                    "ALTER TABLE campaigns ADD COLUMN affected_assets_json TEXT DEFAULT '[]';",
                    "ALTER TABLE campaigns ADD COLUMN affected_identities_json TEXT DEFAULT '[]';",
                    "ALTER TABLE campaigns ADD COLUMN related_alerts_json TEXT DEFAULT '[]';",
                    "ALTER TABLE campaigns ADD COLUMN related_incidents_json TEXT DEFAULT '[]';",
                    "ALTER TABLE campaigns ADD COLUMN analyst_notes_json TEXT DEFAULT '[]';",
                    "ALTER TABLE campaigns ADD COLUMN source_conflicts_json TEXT DEFAULT '[]';",
                    "ALTER TABLE campaigns ADD COLUMN provenance_history_json TEXT DEFAULT '[]';",
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
