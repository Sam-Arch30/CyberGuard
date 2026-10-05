"""create_security_knowledge_graph

Revision ID: d3e1a72b8c4f
Revises: c1f4a82b9e3d
Create Date: 2026-10-05 23:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd3e1a72b8c4f'
down_revision: Union[str, Sequence[str], None] = 'c1f4a82b9e3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Update entities table with canonical_key and workspace_id
    if "entities" in existing_tables:
        entity_cols = {col["name"] for col in inspector.get_columns("entities")}
        with op.batch_alter_table("entities") as batch_op:
            if "canonical_key" not in entity_cols:
                batch_op.add_column(sa.Column("canonical_key", sa.String(500), nullable=True))
                batch_op.create_index("ix_entities_type_key", ["entity_type", "canonical_key"])
            if "workspace_id" not in entity_cols:
                batch_op.add_column(sa.Column("workspace_id", sa.String(100), nullable=True))
                batch_op.create_index("ix_entities_workspace", ["workspace_id"])

    # 2. Update relationships table with origin, status, and workspace_id
    if "relationships" in existing_tables:
        rel_cols = {col["name"] for col in inspector.get_columns("relationships")}
        with op.batch_alter_table("relationships") as batch_op:
            if "origin" not in rel_cols:
                batch_op.add_column(sa.Column("origin", sa.String(50), nullable=False, server_default="OBSERVED"))
            if "status" not in rel_cols:
                batch_op.add_column(sa.Column("status", sa.String(30), nullable=False, server_default="ACTIVE"))
            if "workspace_id" not in rel_cols:
                batch_op.add_column(sa.Column("workspace_id", sa.String(100), nullable=True))
                batch_op.create_index("ix_rel_workspace", ["workspace_id"])

    # 3. Create relationship_observations table
    if "relationship_observations" not in existing_tables:
        op.create_table(
            "relationship_observations",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("relationship_id", sa.String(36), sa.ForeignKey("relationships.id", ondelete="CASCADE"), nullable=False),
            sa.Column("observed_at", sa.DateTime(), nullable=False),
            sa.Column("source_artifact_id", sa.String(36), sa.ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True),
            sa.Column("analysis_run_id", sa.String(36), sa.ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True),
            sa.Column("evidence_id", sa.String(36), sa.ForeignKey("finding_evidence.id", ondelete="SET NULL"), nullable=True),
            sa.Column("analyzer", sa.String(100), nullable=True),
            sa.Column("analyzer_version", sa.String(50), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
            sa.Column("origin", sa.String(50), nullable=False, server_default="OBSERVED"),
            sa.Column("attributes_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_rel_obs_rel_id", "relationship_observations", ["relationship_id"])
        op.create_index("ix_rel_obs_observed_at", "relationship_observations", ["observed_at"])
        op.create_index("ix_rel_obs_artifact_id", "relationship_observations", ["source_artifact_id"])
        op.create_index("ix_rel_obs_run_id", "relationship_observations", ["analysis_run_id"])
        op.create_index("ix_rel_obs_evidence_id", "relationship_observations", ["evidence_id"])
        op.create_index("ix_rel_obs_rel_obs_at", "relationship_observations", ["relationship_id", "observed_at"])


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    if "relationship_observations" in existing_tables:
        op.drop_table("relationship_observations")

    if "relationships" in existing_tables:
        rel_cols = {col["name"] for col in inspector.get_columns("relationships")}
        rel_ixs = {ix["name"] for ix in inspector.get_indexes("relationships")}
        with op.batch_alter_table("relationships") as batch_op:
            if "ix_rel_workspace" in rel_ixs:
                batch_op.drop_index("ix_rel_workspace")
            for col_name in ["workspace_id", "status", "origin"]:
                if col_name in rel_cols:
                    batch_op.drop_column(col_name)

    if "entities" in existing_tables:
        ent_cols = {col["name"] for col in inspector.get_columns("entities")}
        ent_ixs = {ix["name"] for ix in inspector.get_indexes("entities")}
        with op.batch_alter_table("entities") as batch_op:
            if "ix_entities_workspace" in ent_ixs:
                batch_op.drop_index("ix_entities_workspace")
            if "ix_entities_type_key" in ent_ixs:
                batch_op.drop_index("ix_entities_type_key")
            for col_name in ["workspace_id", "canonical_key"]:
                if col_name in ent_cols:
                    batch_op.drop_column(col_name)
