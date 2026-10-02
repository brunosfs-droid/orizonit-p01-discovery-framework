"""v0.6.1 best-effort metadata indexing after filesystem import publication.

Only fixed status codes cross this boundary. No filesystem writes, migrations,
background work, sweeps or retries. The source receipt is reconciliation input.
"""
from pathlib import Path
import P01_PostgreSQL as pg

VERSION = '0.6.1'


class MetadataIndexer:
    def _source(self, store, directory, expected):
        projection = pg.prepare_import(store, directory)
        pg.require(set(expected) == set(pg.IDENTITY) | {'bundle_id'}, 'identity_mismatch')
        pg.require(all(projection.get(key) == value for key, value in expected.items()), 'identity_mismatch')
        return projection

    @staticmethod
    def _failure(exc):
        code = str(exc) if isinstance(exc, pg.PersistenceError) and str(exc) in pg.ERRORS else 'database_failed'
        return {'status': 'pending' if code == 'database_failed' else 'review_required',
                'error_code': code, 'integration_version': VERSION}

    def index(self, store: Path, directory: Path, expected):
        try:
            projection = self._source(store, directory, expected)
            with pg.open_connection() as conn:
                result = pg.index_import(conn, projection)
            return {'status': result['status'], 'integration_version': VERSION}
        except Exception as exc:
            return self._failure(exc)

    def lookup(self, store: Path, directory: Path, expected):
        try:
            projection = self._source(store, directory, expected)
            with pg.open_connection() as conn:
                result = pg.show_import(conn, projection['bundle_id'])
            if result['status'] == 'not_found':
                return {'status': 'pending', 'reason': 'not_indexed', 'integration_version': VERSION}
            for key in (*pg.IDENTITY, 'bundle_sha256', 'receipt_sha256', 'artifacts'):
                pg.require(result[key] == projection[key], 'bundle_conflict')
            return {'status': 'indexed', 'integration_version': VERSION}
        except Exception as exc:
            return self._failure(exc)
