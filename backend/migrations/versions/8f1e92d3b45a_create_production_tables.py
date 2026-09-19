"""create_production_tables

Revision ID: 8f1e92d3b45a
Revises: 64a0d89a8460
Create Date: 2026-09-19 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8f1e92d3b45a'
down_revision: Union[str, Sequence[str], None] = '64a0d89a8460'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create production tables for reports, email analyses, campaigns, analyst decisions, copilot logs, and payloads."""
    # 1. Reports table
    op.create_table('reports',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('report_number', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('case_id', sa.String(length=36), nullable=True),
        sa.Column('evidence_id', sa.String(length=128), nullable=True),
        sa.Column('email_sha256', sa.String(length=64), nullable=True),
        sa.Column('threat_score', sa.Float(), nullable=True, server_default='0.0'),
        sa.Column('severity', sa.String(length=20), nullable=True, server_default='low'),
        sa.Column('analyst_name', sa.String(length=100), nullable=True, server_default='SOC Lead Analyst'),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('ai_summary_json', sa.Text(), nullable=True),
        sa.Column('file_path', sa.String(length=255), nullable=True),
        sa.Column('file_size_bytes', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_reports_report_number'), 'reports', ['report_number'], unique=True)
    op.create_index(op.f('ix_reports_case_id'), 'reports', ['case_id'], unique=False)
    op.create_index(op.f('ix_reports_email_sha256'), 'reports', ['email_sha256'], unique=False)

    # 2. Email Analyses table
    op.create_table('email_analyses',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('evidence_id', sa.String(length=64), nullable=True),
        sa.Column('email_sha256', sa.String(length=64), nullable=True),
        sa.Column('subject', sa.String(length=255), nullable=True, server_default='Untitled Email'),
        sa.Column('sender', sa.String(length=255), nullable=True, server_default='unknown'),
        sa.Column('recipient', sa.String(length=255), nullable=True),
        sa.Column('threat_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='low'),
        sa.Column('spf_result', sa.String(length=20), nullable=True),
        sa.Column('dkim_result', sa.String(length=20), nullable=True),
        sa.Column('dmarc_result', sa.String(length=20), nullable=True),
        sa.Column('domains_json', sa.Text(), nullable=True, server_default='[]'),
        sa.Column('countries_json', sa.Text(), nullable=True, server_default='[]'),
        sa.Column('indicators_json', sa.Text(), nullable=True, server_default='{}'),
        sa.Column('analyzed_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_email_analyses_evidence_id'), 'email_analyses', ['evidence_id'], unique=False)
    op.create_index(op.f('ix_email_analyses_email_sha256'), 'email_analyses', ['email_sha256'], unique=False)
    op.create_index(op.f('ix_email_analyses_severity'), 'email_analyses', ['severity'], unique=False)
    op.create_index(op.f('ix_email_analyses_analyzed_at'), 'email_analyses', ['analyzed_at'], unique=False)

    # 3. Campaigns table
    op.create_table('campaigns',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('campaign_id', sa.String(length=32), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('email_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('recipient_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('sender_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('domain_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('ip_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('asn_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('overall_confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('dominant_attack_type', sa.String(length=100), nullable=False, server_default='Phishing / Fraud'),
        sa.Column('targeted_brands_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('targeted_organizations_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('fingerprint_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('associated_iocs_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('timeline_events_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_campaigns_campaign_id'), 'campaigns', ['campaign_id'], unique=True)

    # 4. Campaign Emails table
    op.create_table('campaign_emails',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('campaign_id', sa.String(length=36), nullable=False),
        sa.Column('email_id', sa.String(length=128), nullable=False),
        sa.Column('email_sha256', sa.String(length=64), nullable=True),
        sa.Column('subject', sa.String(length=255), nullable=True, server_default='Untitled Email'),
        sa.Column('sender', sa.String(length=255), nullable=True, server_default='unknown'),
        sa.Column('recipient', sa.String(length=255), nullable=True),
        sa.Column('sent_at', sa.DateTime(), nullable=False),
        sa.Column('similarity_to_campaign', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('category_scores_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('correlation_reasons_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('added_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['campaign_id'], ['campaigns.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_campaign_emails_campaign_id'), 'campaign_emails', ['campaign_id'], unique=False)
    op.create_index('ix_campaign_emails_camp_email', 'campaign_emails', ['campaign_id', 'email_id'], unique=True)

    # 5. Analyst Decisions table
    op.create_table('analyst_decisions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('email_id_a', sa.String(length=128), nullable=False),
        sa.Column('email_id_b', sa.String(length=128), nullable=False),
        sa.Column('decision', sa.String(length=50), nullable=False),
        sa.Column('campaign_id', sa.String(length=64), nullable=True),
        sa.Column('case_id', sa.String(length=64), nullable=True),
        sa.Column('analyst', sa.String(length=100), nullable=False, server_default='SOC Analyst'),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_analyst_decisions_email_id_a'), 'analyst_decisions', ['email_id_a'], unique=False)
    op.create_index(op.f('ix_analyst_decisions_email_id_b'), 'analyst_decisions', ['email_id_b'], unique=False)
    op.create_index(op.f('ix_analyst_decisions_decision'), 'analyst_decisions', ['decision'], unique=False)
    op.create_index('ix_analyst_decisions_pair', 'analyst_decisions', ['email_id_a', 'email_id_b'], unique=False)

    # 6. Copilot Audit Logs table
    op.create_table('copilot_audit_logs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user', sa.String(length=100), nullable=False, server_default='SOC Analyst'),
        sa.Column('query', sa.Text(), nullable=False),
        sa.Column('mode', sa.String(length=32), nullable=False, server_default='email'),
        sa.Column('context_id', sa.String(length=128), nullable=True),
        sa.Column('evidence_ids_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('confidence', sa.String(length=50), nullable=False, server_default='PROBABLE'),
        sa.Column('model_identifier', sa.String(length=100), nullable=False, server_default='mailtrace-copilot-v1'),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_copilot_audit_logs_timestamp'), 'copilot_audit_logs', ['timestamp'], unique=False)

    # 7. Analysis Payloads table
    op.create_table('analysis_payloads',
        sa.Column('evidence_id', sa.String(length=128), nullable=False),
        sa.Column('analysis_json', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('evidence_id')
    )
    op.create_index(op.f('ix_analysis_payloads_created_at'), 'analysis_payloads', ['created_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('analysis_payloads')
    op.drop_table('copilot_audit_logs')
    op.drop_table('analyst_decisions')
    op.drop_table('campaign_emails')
    op.drop_table('campaigns')
    op.drop_table('email_analyses')
    op.drop_table('reports')
