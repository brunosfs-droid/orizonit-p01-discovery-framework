#!/usr/bin/env python3
"""Opt-in single-workspace lifecycle. No Web adapter, scan or inventory loader."""
from contextlib import contextmanager
from dataclasses import dataclass
import argparse
import json
import math
from pathlib import Path
import secrets
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'persistence'))
import P01_Workspace as ws

pg = ws.pg
VERSION = '0.6.22'
LOCK_KEY = pg.lock_key('server-workspace-coordinator')
ERRORS = ws.ERRORS | {'workspace_runtime_busy', 'workspace_runtime_not_provisioned',
    'workspace_lease_lost', 'workspace_generation_stale', 'workspace_cache_full',
    'workspace_jobs_full', 'workspace_close_pending', 'workspace_connection_mismatch'}


def require_generation(value):
    pg.require(type(value) is int and 0 <= value < 2**63, 'workspace_input_invalid')


def connection_target(conn):
    return conn.info.host, conn.info.port, conn.info.dbname


def authorize(conn, workspace_id, permission, target):
    # Actor grants must come from the same configured installation endpoint.
    # These are trusted libpq connections, never user-submitted DSNs or proxies
    # routing one endpoint to independent databases. Aliases fail closed.
    pg.require(connection_target(conn) == target, 'workspace_connection_mismatch')
    with ws.scope(conn, workspace_id, permission):
        pass


def provision(conn, principal_role):
    """Maintenance only; this role must never be used as a human/content identity."""
    ws.identifier(principal_role)
    pg.guard_connection(conn)
    with conn.transaction():
        pg.timeout(conn); pg.schema_check(conn, minimum=6, model=True); ws.admin(conn)
        role = conn.execute('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=%s', (principal_role,)).fetchone()
        pg.require(role and not any(role), 'workspace_role_invalid')
        conn.execute('SELECT pg_advisory_xact_lock(%s)', (pg.lock_key('coordinator-provision'),))
        old = conn.execute('SELECT principal_role FROM canca.workspace_runtime').fetchone()
        if old:
            pg.require(old[0] == principal_role, 'workspace_conflict')
            return {'status': 'already_provisioned'}
        conn.execute('INSERT INTO canca.workspace_runtime (principal_role) VALUES (%s)', (principal_role,))
    return {'status': 'provisioned'}


class SessionLease:
    """Own a dedicated, unpooled SQL session until shutdown. Calls are serialized."""
    def __init__(self, conn):
        self.conn = conn
        self.target = connection_target(conn)
        self.lease_id = secrets.token_hex(16)
        self.held = False

    def start(self):
        pg.require(not self.held, 'workspace_runtime_busy')
        pg.guard_connection(self.conn)
        try:
            with self.conn.transaction():
                pg.timeout(self.conn); pg.schema_check(self.conn, minimum=6, model=True)
                role = self.conn.execute('SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
                pg.require(role and not role[0], 'workspace_role_invalid')
                self.held = self.conn.execute('SELECT pg_try_advisory_lock(%s)', (LOCK_KEY,)).fetchone()[0]
                pg.require(self.held, 'workspace_runtime_busy')
                if self.conn.execute('SELECT max(version) FROM canca.schema_migrations').fetchone()[0] >= 7:
                    self.conn.execute('UPDATE canca.workspace_runtime SET lease_pid=pg_backend_pid() WHERE singleton')
                row = self.conn.execute('''UPDATE canca.workspace_runtime SET generation=generation+1,
                    state='closed',workspace_id=NULL,lease_id=%s WHERE singleton RETURNING generation''',
                    (self.lease_id,)).fetchone()
                pg.require(row, 'workspace_runtime_not_provisioned')
            return row[0]
        except BaseException:
            self.held = False
            self.conn.close()
            raise

    def check(self, generation):
        unsigned = LOCK_KEY % 2**64
        with self.conn.transaction():
            pg.timeout(self.conn)
            row = self.conn.execute('''SELECT generation FROM canca.workspace_runtime
                WHERE singleton AND lease_id=%s AND EXISTS (SELECT 1 FROM pg_locks
                WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted
                  AND classid=%s::oid AND objid=%s::oid AND objsubid=1)''',
                (self.lease_id, unsigned >> 32, unsigned & 0xffffffff)).fetchone()
            pg.require(self.held and row and row[0] == generation, 'workspace_lease_lost')

    def transition(self, generation, state, workspace_id):
        self.check(generation)
        with self.conn.transaction():
            pg.timeout(self.conn)
            row = self.conn.execute('''UPDATE canca.workspace_runtime SET generation=generation+1,
                state=%s,workspace_id=%s WHERE singleton AND lease_id=%s AND generation=%s
                RETURNING generation''', (state, workspace_id, self.lease_id, generation)).fetchone()
            pg.require(row, 'workspace_lease_lost')
        return row[0]

    def stop(self, generation):
        try:
            self.check(generation)
            with self.conn.transaction():
                pg.timeout(self.conn)
                self.conn.execute('''UPDATE canca.workspace_runtime SET generation=generation+1,
                    state='closed',workspace_id=NULL,lease_id=NULL WHERE singleton AND lease_id=%s''', (self.lease_id,))
        finally:
            # Closing the physical session releases its kernel/database lease even on error.
            self.held = False
            self.conn.close()


@dataclass(frozen=True)
class Token:
    workspace_id: str
    generation: int
    lease_id: str


class Operation:
    def __init__(self, coordinator, actor, token, permission, event):
        self.coordinator, self.actor, self.token = coordinator, actor, token
        self.permission, self.cancel = permission, event
        self.active = True

    def check(self):
        with self.coordinator._operation(self):
            pass

    def cache_get(self, key):
        ws.identifier(key)
        with self.coordinator._operation(self):
            return self.coordinator._cache.get(key)

    def cache_put(self, key, value):
        ws.identifier(key)
        pg.require(type(value) is bytes, 'workspace_input_invalid')
        c = self.coordinator
        with c._operation(self):
            pg.require(len(value) <= c.max_entry_bytes, 'workspace_cache_full')
            size = c._bytes - len(c._cache.get(key, b'')) + len(value)
            pg.require(size <= c.max_cache_bytes and
                       (key in c._cache or len(c._cache) < c.max_cache_entries), 'workspace_cache_full')
            c._cache[key] = value; c._bytes = size


class Coordinator:
    """Trusted server foundation; actor connections are separate from the lease.

    Jobs cancel cooperatively. A failed drain stays closing and cannot open another
    workspace. Consumers must call Operation.check before publishing/committing;
    future SQL adapters also need an atomic revision fence inside their transaction.
    """
    def __init__(self, lease, *, authorizer=authorize, max_jobs=16, max_cache_entries=64,
                 max_cache_bytes=8*1024*1024, max_entry_bytes=1024*1024, heartbeat_seconds=1):
        for value, upper in ((max_jobs,256),(max_cache_entries,4096),
                             (max_cache_bytes,64*1024*1024),(max_entry_bytes,8*1024*1024)):
            pg.require(type(value) is int and 1 <= value <= upper, 'workspace_input_invalid')
        pg.require(type(heartbeat_seconds) in (int,float) and math.isfinite(heartbeat_seconds)
                   and 0.05 <= heartbeat_seconds <= 30, 'workspace_input_invalid')
        self.lease, self.authorizer = lease, authorizer
        self.max_jobs, self.max_cache_entries = max_jobs, max_cache_entries
        self.max_cache_bytes, self.max_entry_bytes = max_cache_bytes, max_entry_bytes
        self._condition = threading.Condition(threading.RLock())
        self._jobs, self._cache, self._bytes = set(), {}, 0
        self._cancel, self._stop = threading.Event(), threading.Event()
        self.state, self.workspace_id = 'closed', None
        self._started, self._terminated = False, False
        self.generation = 0
        self._interval = heartbeat_seconds
        self._heartbeat = None

    def start(self):
        with self._condition:
            pg.require(not self._started and not self._terminated, 'workspace_runtime_busy')
            try:
                self.generation = self.lease.start()
            except Exception as exc:
                code = str(exc) if isinstance(exc, pg.PersistenceError) and str(exc) in ERRORS else 'workspace_lease_lost'
                raise pg.PersistenceError(code) from None
            self._started = True
            self._heartbeat = threading.Thread(target=self._watch, name='canca-workspace-lease', daemon=True)
            self._heartbeat.start()
        return self.generation

    def _fault(self):
        self.state = 'recovery_required'; self._cancel.set()
        self._cache.clear(); self._bytes = 0
        self._condition.notify_all()

    def _live(self):
        pg.require(self._started and not self._terminated and self.state != 'recovery_required', 'workspace_lease_lost')
        try:
            self.lease.check(self.generation)
        except Exception:
            self._fault()
            raise pg.PersistenceError('workspace_lease_lost') from None

    def _transition(self, state, workspace_id):
        try:
            self.generation = self.lease.transition(self.generation, state, workspace_id)
        except Exception:
            self._fault()
            raise pg.PersistenceError('workspace_lease_lost') from None
        self.state, self.workspace_id = state, workspace_id

    def _watch(self):
        while not self._stop.wait(self._interval):
            with self._condition:
                try: self._live()
                except pg.PersistenceError: return

    def open(self, actor, workspace_id, expected_generation):
        ws.identifier(workspace_id); require_generation(expected_generation)
        self.authorizer(actor, workspace_id, 'workspace:read', self.lease.target)
        with self._condition:
            self._live()
            pg.require(expected_generation == self.generation, 'workspace_generation_stale')
            if self.state == 'open' and self.workspace_id == workspace_id:
                return Token(workspace_id, self.generation, self.lease.lease_id)
            pg.require(self.state == 'closed', 'workspace_runtime_busy')
            self._transition('open', workspace_id)
            self._cancel = threading.Event()
            return Token(workspace_id, self.generation, self.lease.lease_id)

    def _token(self, token):
        pg.require(type(token) is Token and self.state == 'open' and token ==
            Token(self.workspace_id, self.generation, self.lease.lease_id), 'workspace_generation_stale')

    @contextmanager
    def borrow(self, actor, token, permission='workspace:read'):
        pg.require(type(token) is Token and permission in ws.PERMISSIONS, 'workspace_input_invalid')
        self.authorizer(actor, token.workspace_id, permission, self.lease.target)
        with self._condition:
            self._live(); self._token(token)
            pg.require(len(self._jobs) < self.max_jobs, 'workspace_jobs_full')
            operation = Operation(self, actor, token, permission, self._cancel)
            self._jobs.add(operation)
        try:
            yield operation
        finally:
            with self._condition:
                operation.active = False; self._jobs.discard(operation); self._condition.notify_all()

    @contextmanager
    def _operation(self, operation):
        self.authorizer(operation.actor, operation.token.workspace_id, operation.permission, self.lease.target)
        with self._condition:
            self._live(); self._token(operation.token)
            pg.require(operation.active and operation in self._jobs and not operation.cancel.is_set(), 'workspace_generation_stale')
            yield

    def snapshot(self, actor):
        with self._condition:
            self._live()
            if self.workspace_id is not None:
                self.authorizer(actor, self.workspace_id, 'workspace:read', self.lease.target)
            return {'state': self.state, 'generation': self.generation, 'workspace_id': self.workspace_id,
                    'jobs': len(self._jobs), 'cache_entries': len(self._cache), 'cache_bytes': self._bytes}

    @staticmethod
    def _deadline(timeout):
        pg.require(type(timeout) in (int,float) and math.isfinite(timeout) and 0 <= timeout <= 30, 'workspace_input_invalid')
        return time.monotonic() + timeout

    def _drain(self, deadline):
        if self.state == 'open':
            self._transition('closing', self.workspace_id)
        closing_generation = self.generation
        self._cancel.set()
        while self._jobs:
            remaining = deadline - time.monotonic()
            pg.require(remaining > 0, 'workspace_close_pending')
            self._condition.wait(remaining)
            self._live()
            pg.require(self.state == 'closing' and self.generation == closing_generation, 'workspace_generation_stale')
        pg.require(self.state == 'closing' and self.generation == closing_generation, 'workspace_generation_stale')
        self._cache.clear(); self._bytes = 0
        self._transition('closed', None)

    def close(self, actor, workspace_id, expected_generation, *, timeout=5):
        ws.identifier(workspace_id); require_generation(expected_generation); deadline = self._deadline(timeout)
        self.authorizer(actor, workspace_id, 'workspace:write', self.lease.target)
        with self._condition:
            self._live()
            pg.require(expected_generation == self.generation, 'workspace_generation_stale')
            if self.state == 'closed': return self.generation
            pg.require(workspace_id == self.workspace_id, 'workspace_generation_stale')
            self._drain(deadline)
            return self.generation

    def shutdown(self, *, timeout=5):
        """Trusted process shutdown. Timeout retains the lease; retry after drain."""
        deadline = self._deadline(timeout)
        with self._condition:
            if self._terminated: return
            pg.require(self._started, 'workspace_lease_lost')
            if self.state != 'recovery_required':
                try:
                    self._live()
                except pg.PersistenceError:
                    if self.state != 'recovery_required': raise
            if self.state == 'recovery_required':
                pg.require(not self._jobs, 'workspace_close_pending')
            elif self.state != 'closed':
                self._drain(deadline)
            self._stop.set(); self._terminated = True
            try: self.lease.stop(self.generation)
            except Exception:
                raise pg.PersistenceError('workspace_lease_lost') from None
        if self._heartbeat is not None: self._heartbeat.join(timeout=1)


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã workspace coordinator v' + VERSION)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('migrate')
    config = commands.add_parser('provision-runtime'); config.add_argument('--principal-role', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'provision-runtime': ws.identifier(args.principal_role)
        with pg.open_connection() as conn:
            result = pg.migrate(conn, runtime=True) if args.command == 'migrate' else provision(conn, args.principal_role)
        print(json.dumps(dict(result, coordinator_version=VERSION)))
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, pg.PersistenceError) and str(exc) in ERRORS else 'database_failed'
        print(json.dumps({'status':'failed','error_code':code,'coordinator_version':VERSION}))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
