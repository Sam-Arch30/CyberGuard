"""create_cross_incident_correlation

Revision ID: e4f2b8c1a93d
Revises: d3e1a72b8c4f
Create Date: 2026-10-06 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e4f2b8c1a93d'
down_revision: Union[str, Sequence[str], None] = 'd3e1a72b8c4f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Update incidents table with workspace_id
    if "incidents" in existing_tables:
        incident_cols = {col["name"] for col in inspector.get_columns("incidents")}
        with op.batch_alter_table("incidents") as batch_op:
            if "workspace_id" not in incident_cols:
                batch_op.add_column(sa.Column("workspace_id", sa.String(64), nullable=False, server_default="default"))
                batch_op.create_index("ix_incidents_workspace_id", ["workspace_id"], unique=False)

    # 2. Update campaigns table with status, workspace_id, engine_version, etc.
    if "campaigns" in existing_tables:
        camp_cols = {col["name"] for col in inspector.get_columns("campaigns")}
        with op.batch_alter_table("campaigns") as batch_op:
            if "status" not in camp_cols:
                batch_op.add_column(sa.Column("status", sa.String(30), nullable=False, server_default="CANDIDATE"))
                batch_op.create_index("ix_campaigns_status", ["status"], unique=False)
            if "workspace_id" not in camp_cols:
                batch_op.add_column(sa.Column("workspace_id", sa.String(64), nullable=False, server_default="default"))
                batch_op.create_index("ix_campaigns_workspace_id", ["workspace_id"], unique=False)
            if "engine_version" not in camp_cols:
                batch_op.add_column(sa.Column("engine_version", sa.String(32), nullable=False, server_default="2.0.0"))
            if "supporting_evidence_json" not in camp_cols:
                batch_op.add_column(sa.Column("supporting_evidence_json", sa.Text(), nullable=False, server_default="[]"))
            if "contradicting_evidence_json" not in camp_cols:
                batch_op.add_column(sa.Column("contradicting_evidence_json", sa.Text(), nullable=False, server_default="[]"))
            if "correlation_summary" not in camp_cols:
                batch_op.add_column(sa.Column("correlation_summary", sa.Text(), nullable=True))

    # 3. Create incident_correlations table
    if "incident_correlations" not in existing_tables:
        op.create_table(
            "incident_correlations",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("workspace_id", sa.String(64), nullable=False, server_default="default"),
            sa.Column("incident_a_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("incident_b_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("correlation_score", sa.Float(), nullable=False, server_default="0.0"),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
            sa.Column("relationship_label", sa.String(100), nullable=False, server_default="Inconclusive / No significant relationship"),
            sa.Column("supporting_evidence_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("contradicting_evidence_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("feature_breakdown_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("shared_indicators_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("status", sa.String(30), nullable=False, server_default="ACTIVE"),
            sa.Column("reviewed_by", sa.String(100), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(), nullable=True),
            sa.Column("review_notes", sa.Text(), nullable=True),
            sa.Column("engine_version", sa.String(32), nullable=False, server_default="2.0.0"),
            sa.Column("config_version", sa.String(32), nullable=False, server_default="2.0.0"),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_incident_correlations_workspace_id", "incident_correlations", ["workspace_id"])
        op.create_index("ix_incident_correlations_incident_a_id", "incident_correlations", ["incident_a_id"])
        op.create_index("ix_incident_correlations_incident_b_id", "incident_correlations", ["incident_b_id"])
        op.create_index("ix_incident_correlations_status", "incident_correlations", ["status"])
        op.create_index("ix_inc_corr_pair", "incident_correlations", ["workspace_id", "incident_a_id", "incident_b_id"], unique=True)
        op.create_index("ix_inc_corr_score", "incident_correlations", ["workspace_id", "correlation_score"])

    # 4. Create campaign_incidents table
    if "campaign_incidents" not in existing_tables:
        op.create_table(
            "campaign_incidents",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("campaign_id", sa.String(36), sa.ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False),
            sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("similarity_score", sa.Float(), nullable=False, server_default="0.0"),
            sa.Column("membership_reasons_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("status", sa.String(30), nullable=False, server_default="CANDIDATE"),
            sa.Column("added_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("added_by", sa.String(100), nullable=False, server_default="AUTOMATED"),
        )
        op.create_index("ix_campaign_incidents_campaign_id", "campaign_incidents", ["campaign_id"])
        op.create_index("ix_campaign_incidents_incident_id", "campaign_incidents", ["incident_id"])
        op.create_index("ix_campaign_incidents_camp_inc", "campaign_incidents", ["campaign_id", "incident_id"], unique=True)


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    if "campaign_incidents" in existing_tables:
        op.drop_table("campaign_incidents")

    if "incident_correlations" in existing_tables:
        op.drop_table("incident_correlations")

    if "campaigns" in existing_tables:
        camp_cols = {col["name"] for col in inspector.get_columns("campaigns")}
        camp_ixs = {ix["name"] for ix in inspector.get_indexes("campaigns")}
        with op.batch_alter_table("campaigns") as batch_op:
            if "ix_campaigns_status" in camp_ixs:
                batch_op.drop_index("ix_campaigns_status")
            if "ix_campaigns_workspace_id" in camp_ixs:
                batch_op.drop_index("ix_campaigns_workspace_id")
            for col_name in [
                "correlation_summary",
                "contradicting_evidence_json",
                "supporting_evidence_json",
                "engine_version",
                "workspace_id",
                "status",
            ]:
                if col_name in camp_cols:
                    batch_op.drop_column(col_name)

    if "incidents" in existing_tables:
        inc_cols = {col["name"] for col in inspector.get_columns("incidents")}
        inc_ixs = {ix["name"] for ix in inspector.get_indexes("incidents")}
        with op.batch_alter_table("incidents") as batch_op:
            if "ix_incidents_workspace_id" in inc_ixs:
                batch_op.drop_index("ix_incidents_workspace_id")
            if "workspace_id" in inc_cols:
                batch_op.drop_column("workspace_id")
