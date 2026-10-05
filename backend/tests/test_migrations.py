import os
import tempfile
import pytest
from pathlib import Path
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine, inspect


def test_alembic_migrations_from_scratch():
    """
    Tests that Alembic migrations run cleanly from base to head on a fresh database,
    verifying production migration safety.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db_path = Path(tmpdir) / "migration_test.db"
        test_db_url = f"sqlite:///{test_db_path}"

        original_db_url = os.environ.get("DATABASE_URL")
        engine = None
        try:
            os.environ["DATABASE_URL"] = test_db_url

            alembic_ini_path = Path(__file__).resolve().parent.parent.parent / "alembic.ini"
            alembic_cfg = Config(str(alembic_ini_path))
            alembic_cfg.set_main_option("sqlalchemy.url", test_db_url)

            # 1. Upgrade from scratch to head
            command.upgrade(alembic_cfg, "head")

            # 2. Inspect created tables
            engine = create_engine(test_db_url)
            inspector = inspect(engine)
            tables = set(inspector.get_table_names())

            expected_tables = {
                "cases",
                "case_emails",
                "case_notes",
                "case_findings",
                "evidence",
                "audit_logs",
                "reports",
                "email_analyses",
                "campaigns",
                "campaign_emails",
                "analyst_decisions",
                "copilot_audit_logs",
                "analysis_payloads",
                "artifacts",
                "analysis_runs",
                "model_versions",
                "findings",
                "finding_evidence",
                "indicators",
                "entities",
                "relationships",
                "incidents",
                "threat_events",
                "response_actions",
                "attack_paths",
                "attack_stages",
                "attack_edges",
                "artifact_storage_records",
                "ingestions",
                "relationship_observations",
                "incident_correlations",
                "campaign_incidents",
                "alembic_version"
            }

            for tbl in expected_tables:
                assert tbl in tables, f"Expected table {tbl} was not created by Alembic migrations"

            # 3. Test downgrade to base
            command.downgrade(alembic_cfg, "base")
            inspector_after_downgrade = inspect(engine)
            tables_after = set(inspector_after_downgrade.get_table_names())
            assert "reports" not in tables_after
            assert "email_analyses" not in tables_after

            # 4. Test re-upgrade to head
            command.upgrade(alembic_cfg, "head")
            inspector_reupgraded = inspect(engine)
            reupgraded_tables = set(inspector_reupgraded.get_table_names())
            for tbl in expected_tables:
                assert tbl in reupgraded_tables, f"Expected table {tbl} missing after re-upgrade"

        finally:
            if engine is not None:
                engine.dispose()
            if original_db_url is not None:
                os.environ["DATABASE_URL"] = original_db_url
            else:
                os.environ.pop("DATABASE_URL", None)
