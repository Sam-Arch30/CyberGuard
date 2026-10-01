"""create_unified_cyberguard_data_model

Revision ID: b7e2a901c43f
Revises: 8f1e92d3b45a
Create Date: 2026-09-25 01:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7e2a901c43f'
down_revision: Union[str, Sequence[str], None] = '8f1e92d3b45a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Creates canonical Unified CyberGuard Data Model tables:
    artifacts, analysis_runs, model_versions, findings, finding_evidence,
    indicators, entities, relationships, incidents, threat_events,
    response_actions, attack_paths, attack_stages, attack_edges.
    Cleans up any legacy unmanaged prototype tables if present and adds request_id to audit_logs.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # 0. Clean up legacy unmanaged prototype tables if present in SQLite
    for orphan in ["email_relationships", "email_iocs", "emails", "iocs"]:
        if orphan in existing_tables:
            op.drop_table(orphan)

    if "analysis_runs" in existing_tables:
        cols = [c["name"] for c in inspector.get_columns("analysis_runs")]
        if "artifact_id" not in cols:
            op.drop_table("analysis_runs")

    # 1. artifacts table
    op.create_table(
        'artifacts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('artifact_type', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False, server_default='UPLOAD'),
        sa.Column('mime_type', sa.String(length=100), nullable=True),
        sa.Column('size', sa.Integer(), nullable=True),
        sa.Column('sha256', sa.String(length=64), nullable=True),
        sa.Column('sha1', sa.String(length=40), nullable=True),
        sa.Column('md5', sa.String(length=32), nullable=True),
        sa.Column('storage_reference', sa.String(length=500), nullable=True),
        sa.Column('parent_artifact_id', sa.String(length=36), nullable=True),
        sa.Column('ingested_at', sa.DateTime(), nullable=False),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['parent_artifact_id'], ['artifacts.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_artifacts_artifact_type'), 'artifacts', ['artifact_type'], unique=False)
    op.create_index(op.f('ix_artifacts_sha256'), 'artifacts', ['sha256'], unique=False)
    op.create_index(op.f('ix_artifacts_parent_artifact_id'), 'artifacts', ['parent_artifact_id'], unique=False)
    op.create_index(op.f('ix_artifacts_ingested_at'), 'artifacts', ['ingested_at'], unique=False)

    # 2. analysis_runs table
    op.create_table(
        'analysis_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('artifact_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='QUEUED'),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('trigger', sa.String(length=50), nullable=False, server_default='USER'),
        sa.Column('pipeline_version', sa.String(length=50), nullable=False, server_default='1.0.0'),
        sa.Column('overall_risk_score', sa.Float(), nullable=True),
        sa.Column('overall_severity', sa.String(length=20), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['artifact_id'], ['artifacts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_analysis_runs_artifact_id'), 'analysis_runs', ['artifact_id'], unique=False)
    op.create_index(op.f('ix_analysis_runs_status'), 'analysis_runs', ['status'], unique=False)
    op.create_index(op.f('ix_analysis_runs_overall_severity'), 'analysis_runs', ['overall_severity'], unique=False)

    # 3. model_versions table
    op.create_table(
        'model_versions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('model_name', sa.String(length=100), nullable=False),
        sa.Column('model_type', sa.String(length=50), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=False),
        sa.Column('provider', sa.String(length=100), nullable=False),
        sa.Column('training_dataset_reference', sa.String(length=255), nullable=True),
        sa.Column('metrics_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='ACTIVE'),
        sa.Column('deployed_at', sa.DateTime(), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_model_versions_name_version', 'model_versions', ['model_name', 'version'], unique=True)
    op.create_index(op.f('ix_model_versions_model_name'), 'model_versions', ['model_name'], unique=False)
    op.create_index(op.f('ix_model_versions_model_type'), 'model_versions', ['model_type'], unique=False)
    op.create_index(op.f('ix_model_versions_version'), 'model_versions', ['version'], unique=False)
    op.create_index(op.f('ix_model_versions_status'), 'model_versions', ['status'], unique=False)

    # 4. findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('analysis_run_id', sa.String(length=36), nullable=False),
        sa.Column('analyzer', sa.String(length=100), nullable=False),
        sa.Column('finding_type', sa.String(length=100), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='LOW'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('risk_contribution', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('method', sa.String(length=50), nullable=False),
        sa.Column('model_version_id', sa.String(length=36), nullable=True),
        sa.Column('rule_id', sa.String(length=100), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['analysis_run_id'], ['analysis_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['model_version_id'], ['model_versions.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_analysis_run_id'), 'findings', ['analysis_run_id'], unique=False)
    op.create_index(op.f('ix_findings_analyzer'), 'findings', ['analyzer'], unique=False)
    op.create_index(op.f('ix_findings_finding_type'), 'findings', ['finding_type'], unique=False)
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'], unique=False)
    op.create_index(op.f('ix_findings_method'), 'findings', ['method'], unique=False)
    op.create_index(op.f('ix_findings_model_version_id'), 'findings', ['model_version_id'], unique=False)
    op.create_index(op.f('ix_findings_rule_id'), 'findings', ['rule_id'], unique=False)

    # 5. finding_evidence table
    op.create_table(
        'finding_evidence',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('evidence_type', sa.String(length=50), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('key', sa.String(length=100), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('artifact_id', sa.String(length=36), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['artifact_id'], ['artifacts.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_finding_evidence_finding_id'), 'finding_evidence', ['finding_id'], unique=False)
    op.create_index(op.f('ix_finding_evidence_evidence_type'), 'finding_evidence', ['evidence_type'], unique=False)
    op.create_index(op.f('ix_finding_evidence_key'), 'finding_evidence', ['key'], unique=False)
    op.create_index(op.f('ix_finding_evidence_artifact_id'), 'finding_evidence', ['artifact_id'], unique=False)

    # 6. indicators table
    op.create_table(
        'indicators',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('indicator_type', sa.String(length=50), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('normalized_value', sa.String(length=500), nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('reputation', sa.String(length=50), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_indicators_type_norm', 'indicators', ['indicator_type', 'normalized_value'], unique=True)
    op.create_index(op.f('ix_indicators_indicator_type'), 'indicators', ['indicator_type'], unique=False)
    op.create_index(op.f('ix_indicators_normalized_value'), 'indicators', ['normalized_value'], unique=False)
    op.create_index(op.f('ix_indicators_first_seen'), 'indicators', ['first_seen'], unique=False)
    op.create_index(op.f('ix_indicators_last_seen'), 'indicators', ['last_seen'], unique=False)
    op.create_index(op.f('ix_indicators_reputation'), 'indicators', ['reputation'], unique=False)

    # 7. entities table
    op.create_table(
        'entities',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('entity_type', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('external_id', sa.String(length=255), nullable=True),
        sa.Column('attributes_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_entities_entity_type'), 'entities', ['entity_type'], unique=False)
    op.create_index(op.f('ix_entities_name'), 'entities', ['name'], unique=False)
    op.create_index(op.f('ix_entities_external_id'), 'entities', ['external_id'], unique=False)

    # 8. relationships table
    op.create_table(
        'relationships',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('source_type', sa.String(length=50), nullable=False),
        sa.Column('source_id', sa.String(length=128), nullable=False),
        sa.Column('relationship_type', sa.String(length=50), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_id', sa.String(length=128), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('evidence_reference', sa.String(length=255), nullable=True),
        sa.Column('analysis_run_id', sa.String(length=36), nullable=True),
        sa.Column('method', sa.String(length=50), nullable=False, server_default='RULE'),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['analysis_run_id'], ['analysis_runs.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_rel_src', 'relationships', ['source_type', 'source_id'], unique=False)
    op.create_index('ix_rel_tgt', 'relationships', ['target_type', 'target_id'], unique=False)
    op.create_index('ix_rel_type_src_tgt', 'relationships', ['relationship_type', 'source_id', 'target_id'], unique=False)
    op.create_index(op.f('ix_relationships_source_type'), 'relationships', ['source_type'], unique=False)
    op.create_index(op.f('ix_relationships_source_id'), 'relationships', ['source_id'], unique=False)
    op.create_index(op.f('ix_relationships_relationship_type'), 'relationships', ['relationship_type'], unique=False)
    op.create_index(op.f('ix_relationships_target_type'), 'relationships', ['target_type'], unique=False)
    op.create_index(op.f('ix_relationships_target_id'), 'relationships', ['target_id'], unique=False)
    op.create_index(op.f('ix_relationships_analysis_run_id'), 'relationships', ['analysis_run_id'], unique=False)

    # 9. incidents table
    op.create_table(
        'incidents',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('incident_number', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='OPEN'),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='MEDIUM'),
        sa.Column('risk_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('opened_at', sa.DateTime(), nullable=False),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.Column('assigned_to', sa.String(length=100), nullable=True),
        sa.Column('legacy_case_id', sa.String(length=36), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incidents_incident_number'), 'incidents', ['incident_number'], unique=True)
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)
    op.create_index(op.f('ix_incidents_severity'), 'incidents', ['severity'], unique=False)
    op.create_index(op.f('ix_incidents_legacy_case_id'), 'incidents', ['legacy_case_id'], unique=False)

    # 10. threat_events table
    op.create_table(
        'threat_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('source_artifact_id', sa.String(length=36), nullable=True),
        sa.Column('analysis_run_id', sa.String(length=36), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='MEDIUM'),
        sa.Column('risk_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='OPEN'),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['analysis_run_id'], ['analysis_runs.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['source_artifact_id'], ['artifacts.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_events_event_type'), 'threat_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_threat_events_timestamp'), 'threat_events', ['timestamp'], unique=False)
    op.create_index(op.f('ix_threat_events_source_artifact_id'), 'threat_events', ['source_artifact_id'], unique=False)
    op.create_index(op.f('ix_threat_events_analysis_run_id'), 'threat_events', ['analysis_run_id'], unique=False)
    op.create_index(op.f('ix_threat_events_severity'), 'threat_events', ['severity'], unique=False)
    op.create_index(op.f('ix_threat_events_status'), 'threat_events', ['status'], unique=False)
    op.create_index(op.f('ix_threat_events_incident_id'), 'threat_events', ['incident_id'], unique=False)

    # 11. response_actions table
    op.create_table(
        'response_actions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('threat_event_id', sa.String(length=36), nullable=True),
        sa.Column('action_type', sa.String(length=50), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='RECOMMENDED'),
        sa.Column('priority', sa.String(length=20), nullable=False, server_default='MEDIUM'),
        sa.Column('recommended_by', sa.String(length=100), nullable=False),
        sa.Column('approved_by', sa.String(length=100), nullable=True),
        sa.Column('executed_by', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('approved_at', sa.DateTime(), nullable=True),
        sa.Column('executed_at', sa.DateTime(), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['threat_event_id'], ['threat_events.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_response_actions_incident_id'), 'response_actions', ['incident_id'], unique=False)
    op.create_index(op.f('ix_response_actions_threat_event_id'), 'response_actions', ['threat_event_id'], unique=False)
    op.create_index(op.f('ix_response_actions_action_type'), 'response_actions', ['action_type'], unique=False)
    op.create_index(op.f('ix_response_actions_status'), 'response_actions', ['status'], unique=False)

    # 12. attack_paths, attack_stages, attack_edges (foundations)
    op.create_table(
        'attack_paths',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='HYPOTHESIS'),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attack_paths_incident_id'), 'attack_paths', ['incident_id'], unique=False)

    op.create_table(
        'attack_stages',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('attack_path_id', sa.String(length=36), nullable=False),
        sa.Column('stage_order', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('technique_id', sa.String(length=50), nullable=True),
        sa.Column('tactic', sa.String(length=100), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='SUSPECTED'),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['attack_path_id'], ['attack_paths.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attack_stages_attack_path_id'), 'attack_stages', ['attack_path_id'], unique=False)
    op.create_index(op.f('ix_attack_stages_technique_id'), 'attack_stages', ['technique_id'], unique=False)

    op.create_table(
        'attack_edges',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('attack_path_id', sa.String(length=36), nullable=False),
        sa.Column('source_stage_id', sa.String(length=36), nullable=False),
        sa.Column('target_stage_id', sa.String(length=36), nullable=False),
        sa.Column('relationship_type', sa.String(length=50), nullable=False, server_default='LEADS_TO'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('metadata_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['attack_path_id'], ['attack_paths.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['source_stage_id'], ['attack_stages.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_stage_id'], ['attack_stages.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attack_edges_attack_path_id'), 'attack_edges', ['attack_path_id'], unique=False)

    # 13. Add request_id column to audit_logs (batch mode for SQLite safety)
    with op.batch_alter_table('audit_logs') as batch_op:
        audit_cols = [c["name"] for c in inspector.get_columns("audit_logs")]
        if "request_id" not in audit_cols:
            batch_op.add_column(sa.Column('request_id', sa.String(length=64), nullable=True))
            batch_op.create_index('ix_audit_logs_request_id', ['request_id'])


def downgrade() -> None:
    """Downgrade schema back to 8f1e92d3b45a."""
    with op.batch_alter_table('audit_logs') as batch_op:
        batch_op.drop_index('ix_audit_logs_request_id')
        batch_op.drop_column('request_id')

    op.drop_table('attack_edges')
    op.drop_table('attack_stages')
    op.drop_table('attack_paths')
    op.drop_table('response_actions')
    op.drop_table('threat_events')
    op.drop_table('incidents')
    op.drop_table('relationships')
    op.drop_table('entities')
    op.drop_table('indicators')
    op.drop_table('finding_evidence')
    op.drop_table('findings')
    op.drop_table('model_versions')
    op.drop_table('analysis_runs')
    op.drop_table('artifacts')
