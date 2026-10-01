"""create_evidence_storage_and_ingestion_records

Revision ID: c1f4a82b9e3d
Revises: b7e2a901c43f
Create Date: 2026-10-01 22:46:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1f4a82b9e3d'
down_revision: Union[str, Sequence[str], None] = 'b7e2a901c43f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Create artifact_storage_records
    if "artifact_storage_records" not in existing_tables:
        op.create_table(
            "artifact_storage_records",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("artifact_id", sa.String(36), sa.ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False),
            sa.Column("storage_backend", sa.String(50), nullable=False, server_default="LOCAL"),
            sa.Column("storage_key", sa.String(500), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("size", sa.Integer(), nullable=False),
            sa.Column("mime_type", sa.String(100), nullable=True),
            sa.Column("original_filename", sa.String(255), nullable=True),
            sa.Column("stored_at", sa.DateTime(), nullable=False),
            sa.Column("verified_at", sa.DateTime(), nullable=True),
            sa.Column("integrity_status", sa.String(30), nullable=False, server_default="UNVERIFIED"),
            sa.Column("retention_policy", sa.String(50), nullable=False, server_default="INDEFINITE"),
            sa.Column("retain_until", sa.DateTime(), nullable=True),
            sa.Column("legal_hold", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_artifact_storage_records_artifact_id", "artifact_storage_records", ["artifact_id"])
        op.create_index("ix_artifact_storage_records_backend", "artifact_storage_records", ["storage_backend"])
        op.create_index("ix_artifact_storage_records_key", "artifact_storage_records", ["storage_key"])
        op.create_index("ix_artifact_storage_records_sha256", "artifact_storage_records", ["sha256"])
        op.create_index("ix_artifact_storage_records_integrity", "artifact_storage_records", ["integrity_status"])

    # 2. Create ingestions
    if "ingestions" not in existing_tables:
        op.create_table(
            "ingestions",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("artifact_id", sa.String(36), sa.ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False),
            sa.Column("source", sa.String(50), nullable=False, server_default="UPLOAD"),
            sa.Column("submitted_by", sa.String(100), nullable=True),
            sa.Column("received_at", sa.DateTime(), nullable=False),
            sa.Column("original_filename", sa.String(255), nullable=True),
            sa.Column("request_id", sa.String(100), nullable=True),
            sa.Column("context_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("status", sa.String(30), nullable=False, server_default="COMPLETED"),
            sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_ingestions_artifact_id", "ingestions", ["artifact_id"])
        op.create_index("ix_ingestions_source", "ingestions", ["source"])
        op.create_index("ix_ingestions_received_at", "ingestions", ["received_at"])
        op.create_index("ix_ingestions_request_id", "ingestions", ["request_id"])
        op.create_index("ix_ingestions_status", "ingestions", ["status"])

    # 3. Additive columns on reports
    if "reports" in existing_tables:
        report_columns = {col["name"] for col in inspector.get_columns("reports")}
        with op.batch_alter_table("reports") as batch_op:
            if "artifact_id" not in report_columns:
                batch_op.add_column(sa.Column("artifact_id", sa.String(36), nullable=True))
                batch_op.create_index("ix_reports_artifact_id", ["artifact_id"])
            if "analysis_run_id" not in report_columns:
                batch_op.add_column(sa.Column("analysis_run_id", sa.String(36), nullable=True))
                batch_op.create_index("ix_reports_analysis_run_id", ["analysis_run_id"])
            if "sha256" not in report_columns:
                batch_op.add_column(sa.Column("sha256", sa.String(64), nullable=True))
                batch_op.create_index("ix_reports_sha256", ["sha256"])
            if "format" not in report_columns:
                batch_op.add_column(sa.Column("format", sa.String(20), nullable=False, server_default="PDF"))
            if "generator_version" not in report_columns:
                batch_op.add_column(sa.Column("generator_version", sa.String(50), nullable=False, server_default="1.0.0"))


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    if "ingestions" in existing_tables:
        op.drop_table("ingestions")
    if "artifact_storage_records" in existing_tables:
        op.drop_table("artifact_storage_records")

    if "reports" in existing_tables:
        report_columns = {col["name"] for col in inspector.get_columns("reports")}
        report_indexes = {ix["name"] for ix in inspector.get_indexes("reports")}
        with op.batch_alter_table("reports") as batch_op:
            for ix_name in ["ix_reports_sha256", "ix_reports_analysis_run_id", "ix_reports_artifact_id"]:
                if ix_name in report_indexes:
                    batch_op.drop_index(ix_name)
            for col_name in ["generator_version", "format", "sha256", "analysis_run_id", "artifact_id"]:
                if col_name in report_columns:
                    batch_op.drop_column(col_name)
