"""Additive ownership upgrade, shared by startup and Alembic."""
from sqlalchemy import inspect, text, literal

def upgrade_workspace_ownership(conn, metadata):
    for table in metadata.sorted_tables:
        columns = {column['name'] for column in inspect(conn).get_columns(table.name)}
        quoted = conn.dialect.identifier_preparer.quote(table.name)
        for column in table.columns:
            if column.name in columns:
                continue
            if column.primary_key:
                raise RuntimeError(f'Legacy table {table.name} is missing its primary key; manual migration required.')
            name = conn.dialect.identifier_preparer.quote(column.name)
            kind = column.type.compile(dialect=conn.dialect)
            default = " DEFAULT 'default' NOT NULL" if column.name == 'workspace_id' else ''
            # Historical values stay unknown where no scalar default exists. Do not
            # manufacture timestamps or inferred detector/source provenance.
            if column.name != 'workspace_id' and column.default is not None and column.default.is_scalar and column.name != 'source_type':
                value = literal(column.default.arg).compile(dialect=conn.dialect, compile_kwargs={'literal_binds':True})
                default = f' DEFAULT {value}'
            conn.execute(text(f'ALTER TABLE {quoted} ADD COLUMN {name} {kind}{default}'))
        conn.execute(text(f"UPDATE {quoted} SET workspace_id = 'default' WHERE workspace_id IS NULL OR workspace_id = ''"))
        existing = {index['name']:index for index in inspect(conn).get_indexes(table.name)}
        for index in table.indexes:
            present = existing.get(index.name)
            if present and present['column_names'] != [column.name for column in index.columns]:
                name = conn.dialect.identifier_preparer.quote(index.name)
                conn.execute(text(f'DROP INDEX {name}'))
                index.create(bind=conn)
