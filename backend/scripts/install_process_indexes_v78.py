"""Run from /app: python scripts/install_process_indexes_v78.py [--schema firm_x].

Online expression indexes for NOT EXISTS completeness joins. Does not recreate
an existing index with different definitions or retry an invalid concurrent build.
"""
import argparse
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sqlalchemy import text
from app.db.session import engine


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--schema')
    args=parser.parse_args()
    with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as conn:
        schemas=[args.schema] if args.schema else [r[0] for r in conn.execute(text('SELECT schema_name FROM public.firms'))]
        quote=engine.dialect.identifier_preparer.quote
        for schema in schemas:
            if not conn.execute(text('SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name=:s)'),{'s':schema}).scalar():
                raise ValueError('Unknown firm schema')
            table=f'{quote(schema)}.rag_chunks'
            if not conn.execute(text('SELECT to_regclass(:t)'),{'t':table}).scalar():
                continue
            definitions=[
                ('ix_rag_mobile_completion_v78',"(job_id,(metadata->>'mobile_artifact_id'),(metadata->>'chunk_policy')) WHERE metadata->>'serial_pipeline'='true'"),
                ('ix_rag_priority_completion_v78',"(job_id,(metadata->>'priority_artifact_id'),(metadata->>'chunk_policy')) WHERE metadata->>'priority_artifact_id' IS NOT NULL"),
            ]
            for name,definition in definitions:
                existing=conn.execute(text('SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid=to_regclass(:n)'),{'n':f'{quote(schema)}.{quote(name)}'}).scalar()
                if existing is False:
                    raise RuntimeError(f'Invalid index {schema}.{name}; inspect and repair its interrupted build before retrying')
                conn.execute(text(f'CREATE INDEX CONCURRENTLY IF NOT EXISTS {quote(name)} ON {table} {definition}'))
            conn.execute(text(f'ANALYZE {table}'))
            print(f'Installed completion indexes: {schema}')

if __name__=='__main__':
    main()
