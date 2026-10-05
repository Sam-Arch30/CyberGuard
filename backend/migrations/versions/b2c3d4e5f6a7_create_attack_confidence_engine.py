"""create_attack_confidence_engine

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-10-06 02:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
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
            if "confidence_level" not in existing_cols:
                batch_op.add_column(sa.Column("confidence_level", sa.String(30), nullable=False, server_default="MODERATE"))
            if "confidence_breakdown_json" not in existing_cols:
                batch_op.add_column(sa.Column("confidence_breakdown_json", sa.Text(), nullable=False, server_default="{}"))
            if "explanation_json" not in existing_cols:
                batch_op.add_column(sa.Column("explanation_json", sa.Text(), nullable=False, server_default="{}"))
            if "confidence_bottleneck_json" not in existing_cols:
                batch_op.add_column(sa.Column("confidence_bottleneck_json", sa.Text(), nullable=False, server_default="{}"))

    # 2. Update attack_stages table columns
    if "attack_stages" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_stages")}
        with op.batch_alter_table("attack_stages") as batch_op:
            if "confidence_level" not in existing_cols:
                batch_op.add_column(sa.Column("confidence_level", sa.String(30), nullable=False, server_default="HIGH"))
            if "confidence_breakdown_json" not in existing_cols:
                batch_op.add_column(sa.Column("confidence_breakdown_json", sa.Text(), nullable=False, server_default="{}"))
            if "explanation_json" not in existing_cols:
                batch_op.add_column(sa.Column("explanation_json", sa.Text(), nullable=False, server_default="{}"))

    # 3. Update attack_edges table columns
    if "attack_edges" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_edges")}
        with op.batch_alter_table("attack_edges") as batch_op:
            if "confidence_level" not in existing_cols:
                batch_op.add_column(sa.Column("confidence_level", sa.String(30), nullable=False, server_default="HIGH"))
            if "confidence_breakdown_json" not in existing_cols:
                batch_op.add_column(sa.Column("confidence_breakdown_json", sa.Text(), nullable=False, server_default="{}"))
            if "explanation_json" not in existing_cols:
                batch_op.add_column(sa.Column("explanation_json", sa.Text(), nullable=False, server_default="{}"))

    # 4. Update attack_hypotheses table columns
    if "attack_hypotheses" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_hypotheses")}
        with op.batch_alter_table("attack_hypotheses") as batch_op:
            if "confidence_level" not in existing_cols:
                batch_op.add_column(sa.Column("confidence_level", sa.String(30), nullable=False, server_default="MODERATE"))
            if "confidence_breakdown_json" not in existing_cols:
                batch_op.add_column(sa.Column("confidence_breakdown_json", sa.Text(), nullable=False, server_default="{}"))
            if "explanation_json" not in existing_cols:
                batch_op.add_column(sa.Column("explanation_json", sa.Text(), nullable=False, server_default="{}"))


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    if "attack_hypotheses" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_hypotheses")}
        with op.batch_alter_table("attack_hypotheses") as batch_op:
            if "explanation_json" in existing_cols:
                batch_op.drop_column("explanation_json")
            if "confidence_breakdown_json" in existing_cols:
                batch_op.drop_column("confidence_breakdown_json")
            if "confidence_level" in existing_cols:
                batch_op.drop_column("confidence_level")

    if "attack_edges" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_edges")}
        with op.batch_alter_table("attack_edges") as batch_op:
            if "explanation_json" in existing_cols:
                batch_op.drop_column("explanation_json")
            if "confidence_breakdown_json" in existing_cols:
                batch_op.drop_column("confidence_breakdown_json")
            if "confidence_level" in existing_cols:
                batch_op.drop_column("confidence_level")

    if "attack_stages" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_stages")}
        with op.batch_alter_table("attack_stages") as batch_op:
            if "explanation_json" in existing_cols:
                batch_op.drop_column("explanation_json")
            if "confidence_breakdown_json" in existing_cols:
                batch_op.drop_column("confidence_breakdown_json")
            if "confidence_level" in existing_cols:
                batch_op.drop_column("confidence_level")

    if "attack_paths" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("attack_paths")}
        with op.batch_alter_table("attack_paths") as batch_op:
            if "confidence_bottleneck_json" in existing_cols:
                batch_op.drop_column("confidence_bottleneck_json")
            if "explanation_json" in existing_cols:
                batch_op.drop_column("explanation_json")
            if "confidence_breakdown_json" in existing_cols:
                batch_op.drop_column("confidence_breakdown_json")
            if "confidence_level" in existing_cols:
                batch_op.drop_column("confidence_level")
