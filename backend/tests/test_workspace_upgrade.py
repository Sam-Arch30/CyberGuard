from sqlalchemy import create_engine, text
from backend.db.session import Base
from backend.db.workspace_schema import upgrade_workspace_ownership

def test_additive_upgrade_preserves_legacy_indicator_and_tenant_uniqueness(tmp_path):
    engine=create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as conn:
        conn.execute(text('CREATE TABLE indicators (id VARCHAR(36) PRIMARY KEY, indicator_type VARCHAR(50), value TEXT, normalized_value VARCHAR(500))'))
        conn.execute(text('CREATE UNIQUE INDEX ix_indicators_type_norm ON indicators(indicator_type, normalized_value)'))
        conn.execute(text("INSERT INTO indicators VALUES ('preserved','DOMAIN','Example.test','example.test')"))
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        upgrade_workspace_ownership(conn,Base.metadata)
        upgrade_workspace_ownership(conn,Base.metadata)
        assert tuple(conn.execute(text('SELECT id,value,workspace_id FROM indicators')).one())==('preserved','Example.test','default')
        conn.execute(text("INSERT INTO indicators (id,indicator_type,value,normalized_value,workspace_id) VALUES ('tenant-b','DOMAIN','Example.test','example.test','tenant-b')"))
        assert conn.execute(text('SELECT COUNT(*) FROM indicators')).scalar()==2
    engine.dispose()

def test_old_findings_schema_gains_columns_without_inventing_provenance(tmp_path):
    engine=create_engine(f"sqlite:///{tmp_path / 'old-findings.db'}")
    with engine.begin() as conn:
        conn.execute(text('CREATE TABLE findings (id VARCHAR(36) PRIMARY KEY, title TEXT, analyzer VARCHAR(100))'))
        conn.execute(text("INSERT INTO findings VALUES ('old-finding','Preserved finding','legacy-analyzer')"))
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        upgrade_workspace_ownership(conn,Base.metadata)
        upgrade_workspace_ownership(conn,Base.metadata)
        row=conn.execute(text('SELECT id,title,analyzer,source_type,workspace_id FROM findings')).one()
        assert tuple(row)==('old-finding','Preserved finding','legacy-analyzer',None,'default')
    from sqlalchemy import inspect
    for table in Base.metadata.sorted_tables:
        present={column['name'] for column in inspect(engine).get_columns(table.name)}
        assert set(table.columns.keys()).issubset(present)
    engine.dispose()
