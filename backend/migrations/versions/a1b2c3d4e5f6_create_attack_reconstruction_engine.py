"""create_attack_reconstruction_engine

Revision ID: a1b2c3d4e5f6
Revises: f5a1c3d7b92e
Create Date: 2026-10-06 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'f5a1c3d7b92e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Update attack_paths table columns
    if "attack_paths" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_paths")}
        with op.batch_alter_table("attack_paths") as batch_op:
            if "workspace_id" not in existing_cols:
                batch_op.add_column(sa.Column("workspace_id", sa.String(64), nullable=False, server_default="default"))
            if "classification" not in existing_cols:
                batch_op.add_column(sa.Column("classification", sa.String(50), nullable=False, server_default="PLAUSIBLE_RECONSTRUCTION"))
            if "start_time" not in existing_cols:
                batch_op.add_column(sa.Column("start_time", sa.DateTime(), nullable=True))
            if "end_time" not in existing_cols:
                batch_op.add_column(sa.Column("end_time", sa.DateTime(), nullable=True))
            if "supporting_evidence_json" not in existing_cols:
                batch_op.add_column(sa.Column("supporting_evidence_json", sa.Text(), nullable=False, server_default="[]"))
            if "contradicting_evidence_json" not in existing_cols:
                batch_op.add_column(sa.Column("contradicting_evidence_json", sa.Text(), nullable=False, server_default="[]"))
            if "evidence_gaps_json" not in existing_cols:
                batch_op.add_column(sa.Column("evidence_gaps_json", sa.Text(), nullable=False, server_default="[]"))
            if "alternative_hypotheses_json" not in existing_cols:
                batch_op.add_column(sa.Column("alternative_hypotheses_json", sa.Text(), nullable=False, server_default="[]"))
            if "version" not in existing_cols:
                batch_op.add_column(sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
            if "engine_version" not in existing_cols:
                batch_op.add_column(sa.Column("engine_version", sa.String(32), nullable=False, server_default="1.0.0"))
            if "rule_version" not in existing_cols:
                batch_op.add_column(sa.Column("rule_version", sa.String(32), nullable=False, server_default="1.0.0"))
            if "analyst_disposition" not in existing_cols:
                batch_op.add_column(sa.Column("analyst_disposition", sa.String(50), nullable=True))
            if "analyst_notes" not in existing_cols:
                batch_op.add_column(sa.Column("analyst_notes", sa.Text(), nullable=True))
            if "reviewed_by" not in existing_cols:
                batch_op.add_column(sa.Column("reviewed_by", sa.String(100), nullable=True))
            if "reviewed_at" not in existing_cols:
                batch_op.add_column(sa.Column("reviewed_at", sa.DateTime(), nullable=True))

    # 2. Update attack_stages table columns
    if "attack_stages" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_stages")}
        with op.batch_alter_table("attack_stages") as batch_op:
            if "stage_type" not in existing_cols:
                batch_op.add_column(sa.Column("stage_type", sa.String(50), nullable=False, server_default="UNKNOWN_ACTIVITY"))
            if "stage_status" not in existing_cols:
                batch_op.add_column(sa.Column("stage_status", sa.String(30), nullable=False, server_default="OBSERVED"))
            if "start_time" not in existing_cols:
                batch_op.add_column(sa.Column("start_time", sa.DateTime(), nullable=True))
            if "end_time" not in existing_cols:
                batch_op.add_column(sa.Column("end_time", sa.DateTime(), nullable=True))
            if "confidence" not in existing_cols:
                batch_op.add_column(sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"))
            if "entity_ids_json" not in existing_cols:
                batch_op.add_column(sa.Column("entity_ids_json", sa.Text(), nullable=False, server_default="[]"))
            if "event_ids_json" not in existing_cols:
                batch_op.add_column(sa.Column("event_ids_json", sa.Text(), nullable=False, server_default="[]"))
            if "finding_ids_json" not in existing_cols:
                batch_op.add_column(sa.Column("finding_ids_json", sa.Text(), nullable=False, server_default="[]"))
            if "evidence_ids_json" not in existing_cols:
                batch_op.add_column(sa.Column("evidence_ids_json", sa.Text(), nullable=False, server_default="[]"))
            if "relationship_ids_json" not in existing_cols:
                batch_op.add_column(sa.Column("relationship_ids_json", sa.Text(), nullable=False, server_default="[]"))
            if "supporting_evidence_json" not in existing_cols:
                batch_op.add_column(sa.Column("supporting_evidence_json", sa.Text(), nullable=False, server_default="[]"))
            if "contradicting_evidence_json" not in existing_cols:
                batch_op.add_column(sa.Column("contradicting_evidence_json", sa.Text(), nullable=False, server_default="[]"))
            if "limitations_json" not in existing_cols:
                batch_op.add_column(sa.Column("limitations_json", sa.Text(), nullable=False, server_default="[]"))
            if "analyst_disposition" not in existing_cols:
                batch_op.add_column(sa.Column("analyst_disposition", sa.String(50), nullable=True))
            if "analyst_notes" not in existing_cols:
                batch_op.add_column(sa.Column("analyst_notes", sa.Text(), nullable=True))

    # 3. Update attack_edges table columns
    if "attack_edges" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_edges")}
        with op.batch_alter_table("attack_edges") as batch_op:
            if "edge_status" not in existing_cols:
                batch_op.add_column(sa.Column("edge_status", sa.String(30), nullable=False, server_default="DERIVED"))
            if "temporal_gap_seconds" not in existing_cols:
                batch_op.add_column(sa.Column("temporal_gap_seconds", sa.Float(), nullable=True))
            if "shared_entities_json" not in existing_cols:
                batch_op.add_column(sa.Column("shared_entities_json", sa.Text(), nullable=False, server_default="[]"))
            if "supporting_evidence_json" not in existing_cols:
                batch_op.add_column(sa.Column("supporting_evidence_json", sa.Text(), nullable=False, server_default="[]"))
            if "contradicting_evidence_json" not in existing_cols:
                batch_op.add_column(sa.Column("contradicting_evidence_json", sa.Text(), nullable=False, server_default="[]"))
            if "analyst_disposition" not in existing_cols:
                batch_op.add_column(sa.Column("analyst_disposition", sa.String(50), nullable=True))
            if "analyst_notes" not in existing_cols:
                batch_op.add_column(sa.Column("analyst_notes", sa.Text(), nullable=True))

    # 4. Create attack_hypotheses table
    if "attack_hypotheses" not in existing_tables:
        op.create_table(
            "attack_hypotheses",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("attack_path_id", sa.String(36), sa.ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=True),
            sa.Column("workspace_id", sa.String(64), nullable=False, server_default="default"),
            sa.Column("title", sa.String(255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("status", sa.String(50), nullable=False, server_default="PLAUSIBLE"),
            sa.Column("is_primary", sa.Boolean(), nullable=False, server_default="0"),
            sa.Column("stage_ids_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
            sa.Column("supporting_evidence_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("contradicting_evidence_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("missing_evidence_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("analyst_disposition", sa.String(50), nullable=True),
            sa.Column("analyst_notes", sa.Text(), nullable=True),
            sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_attack_hypotheses_incident_id", "attack_hypotheses", ["incident_id"], unique=False)
        op.create_index("ix_attack_hypotheses_attack_path_id", "attack_hypotheses", ["attack_path_id"], unique=False)
        op.create_index("ix_attack_hypotheses_workspace_id", "attack_hypotheses", ["workspace_id"], unique=False)
        op.create_index("ix_attack_hypotheses_status", "attack_hypotheses", ["status"], unique=False)


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    if "attack_hypotheses" in existing_tables:
        op.drop_table("attack_hypotheses")

    if "attack_edges" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_edges")}
        with op.batch_alter_table("attack_edges") as batch_op:
            for col in ["edge_status", "temporal_gap_seconds", "shared_entities_json", "supporting_evidence_json", "contradicting_evidence_json", "analyst_disposition", "analyst_notes"]:
                if col in existing_cols:
                    batch_op.drop_column(col)

    if "attack_stages" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_stages")}
        with op.batch_alter_table("attack_stages") as batch_op:
            for col in ["stage_type", "stage_status", "start_time", "end_time", "confidence", "entity_ids_json", "event_ids_json", "finding_ids_json", "evidence_ids_json", "relationship_ids_json", "supporting_evidence_json", "contradicting_evidence_json", "limitations_json", "analyst_disposition", "analyst_notes"]:
                if col in existing_cols:
                    batch_op.drop_column(col)

    if "attack_paths" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_paths")}
        with op.batch_alter_table("attack_paths") as batch_op:
            for col in ["workspace_id", "classification", "start_time", "end_time", "supporting_evidence_json", "contradicting_evidence_json", "evidence_gaps_json", "alternative_hypotheses_json", "version", "engine_version", "rule_version", "analyst_disposition", "analyst_notes", "reviewed_by", "reviewed_at"]:
                if col in existing_cols:
                    batch_op.drop_column(col)
