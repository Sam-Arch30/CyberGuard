"""Persist workspace ownership and tenant-sensitive uniqueness without deleting evidence."""
from alembic import op
from backend.db.session import Base
import backend.db.models
from backend.db.workspace_schema import upgrade_workspace_ownership
revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None

def upgrade():
    conn = op.get_bind()
    Base.metadata.create_all(bind=conn)
    upgrade_workspace_ownership(conn, Base.metadata)

def downgrade():
    # Retain ownership and evidence during rollback; destructive reversal is unsafe.
    pass
