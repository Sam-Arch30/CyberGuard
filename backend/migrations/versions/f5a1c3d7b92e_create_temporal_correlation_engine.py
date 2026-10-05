"""create_temporal_correlation_engine

Revision ID: f5a1c3d7b92e
Revises: e4f2b8c1a93d
Create Date: 2026-10-06 00:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f5a1c3d7b92e'
down_revision: Union[str, Sequence[str], None] = 'e4f2b8c1a93d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Create security_events table
    if "security_events" not in existing_tables:
        op.create_table(
            "security_events",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("event_type", sa.String(100), nullable=False),
            sa.Column("event_time", sa.DateTime(), nullable=False),
            sa.Column("event_time_end", sa.DateTime(), nullable=True),
            sa.Column("event_time_precision", sa.String(30), nullable=False, server_default="SECOND"),
            sa.Column("event_time_confidence", sa.Float(), nullable=False, server_default="1.0"),
            sa.Column("ingested_at", sa.DateTime(), nullable=False),
            sa.Column("analyzed_at", sa.DateTime(), nullable=True),
            sa.Column("source_type", sa.String(50), nullable=False),
            sa.Column("source_artifact_id", sa.String(36), sa.ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True),
            sa.Column("analysis_run_id", sa.String(36), sa.ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True),
            sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
            sa.Column("workspace_id", sa.String(64), nullable=False, server_default="default"),
            sa.Column("entity_ids_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("finding_ids_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("threat_event_ids_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("provider", sa.String(100), nullable=False, server_default="generic"),
            sa.Column("adapter", sa.String(100), nullable=False, server_default="generic"),
            sa.Column("adapter_version", sa.String(32), nullable=False, server_default="1.0.0"),
            sa.Column("attributes_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("timestamp_provenance_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_security_events_event_type", "security_events", ["event_type"], unique=False)
        op.create_index("ix_security_events_event_time", "security_events", ["event_time"], unique=False)
        op.create_index("ix_security_events_ingested_at", "security_events", ["ingested_at"], unique=False)
        op.create_index("ix_security_events_source_type", "security_events", ["source_type"], unique=False)
        op.create_index("ix_security_events_source_artifact_id", "security_events", ["source_artifact_id"], unique=False)
        op.create_index("ix_security_events_analysis_run_id", "security_events", ["analysis_run_id"], unique=False)
        op.create_index("ix_security_events_incident_id", "security_events", ["incident_id"], unique=False)
        op.create_index("ix_security_events_workspace_id", "security_events", ["workspace_id"], unique=False)
        op.create_index("ix_sec_ev_inc_time", "security_events", ["incident_id", "event_time"], unique=False)
        op.create_index("ix_sec_ev_ws_time", "security_events", ["workspace_id", "event_time"], unique=False)
        op.create_index("ix_sec_ev_type_time", "security_events", ["event_type", "event_time"], unique=False)

    # 2. Create temporal_sequences table
    if "temporal_sequences" not in existing_tables:
        op.create_table(
            "temporal_sequences",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("workspace_id", sa.String(64), nullable=False, server_default="default"),
            sa.Column("event_ids_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("rule_ids_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("start_time", sa.DateTime(), nullable=False),
            sa.Column("end_time", sa.DateTime(), nullable=False),
            sa.Column("duration_seconds", sa.Float(), nullable=False, server_default="0.0"),
            sa.Column("shared_entities_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("supporting_evidence_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("conflicting_evidence_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("limitations_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
            sa.Column("status", sa.String(50), nullable=False, server_default="OBSERVED_SEQUENCE"),
            sa.Column("summary", sa.Text(), nullable=False),
            sa.Column("engine_version", sa.String(32), nullable=False, server_default="1.0.0"),
            sa.Column("rule_version", sa.String(32), nullable=False, server_default="1.0.0"),
            sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_temporal_sequences_incident_id", "temporal_sequences", ["incident_id"], unique=False)
        op.create_index("ix_temporal_sequences_workspace_id", "temporal_sequences", ["workspace_id"], unique=False)
        op.create_index("ix_temporal_sequences_start_time", "temporal_sequences", ["start_time"], unique=False)
        op.create_index("ix_temporal_sequences_end_time", "temporal_sequences", ["end_time"], unique=False)
        op.create_index("ix_temporal_sequences_status", "temporal_sequences", ["status"], unique=False)
        op.create_index("ix_temp_seq_inc_time", "temporal_sequences", ["incident_id", "start_time"], unique=False)
        op.create_index("ix_temp_seq_ws_status", "temporal_sequences", ["workspace_id", "status"], unique=False)


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    if "temporal_sequences" in existing_tables:
        op.drop_table("temporal_sequences")

    if "security_events" in existing_tables:
        op.drop_table("security_events")
