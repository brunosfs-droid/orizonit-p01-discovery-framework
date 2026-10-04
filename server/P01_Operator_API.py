#!/usr/bin/env python3
"""Separate local-operator API; authenticated exact-scope read-only reports."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import re
import ssl
import sys
import threading
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'persistence'))
from P01_Operator_Auth import AccessError, LocalAuth, load_policy, unique_object
import P01_Assessment_Report as report
import P01_Operator_Audit as audit

VERSION = '0.6.11'
MAX_BODY = 4096
MAX_RESPONSE = 32 * 1024 * 1024
MAX_WORKERS = 8
REPORT_PATH = re.compile(r'/api/v1/assessments/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/report')


class OperatorService:
    def __init__(self, auth):
        if not isinstance(auth, LocalAuth):
            raise ValueError('validated local auth required')
        self.auth = auth

    def read_report(self, token, assessment_id, *, after_analysis_id='', after_ordinal=-1,
                    limit=100, expected_scope_sha256=None):
        self.auth.require(token, assessment_id)
        params = (assessment_id, after_analysis_id, after_ordinal, limit, expected_scope_sha256)
        report.validate_query(*params)
        with report.pg.open_connection() as conn:
            return report.show_assessment(conn, *params)


class OperatorServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    request_queue_size = MAX_WORKERS

    def __init__(self, address, service):
        self.service = service
        self.audit = None
        self._slots = threading.BoundedSemaphore(MAX_WORKERS)
        super().__init__(address, OperatorHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            if getattr(self, 'tls_context', None) is not None:
                request = self.tls_context.wrap_socket(request, server_side=True)
            super().process_request_thread(request, client_address)
        except Exception:
            self.shutdown_request(request)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        # No traceback can expose backend connection, credential or request data.
        pass

    def server_close(self):
        try:
            super().server_close()
        finally:
            if self.audit is not None:
                self.audit.close()


class OperatorHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    server_version = 'CancaOperator/' + VERSION
    sys_version = ''

    def log_message(self, format, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self._send(code, dict(status='failed', error_code='http_request_invalid'))

    def send_response(self, code, message=None):
        self._audit_http_status = code
        super().send_response(code, message)

    def _send(self, status, payload):
        try:
            raw = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode('utf-8')
            if len(raw) > MAX_RESPONSE:
                raise ValueError('response limit')
        except (ValueError, UnicodeError, TypeError):
            status = 503
            raw = b'{"status":"failed","error_code":"report_response_invalid"}'
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
        self.send_header('Connection', 'close')
        self.close_connection = True
        self.end_headers()
        self.wfile.write(raw)

    def _header(self, key):
        values = self.headers.get_all(key, [])
        if len(values) > 1:
            raise AccessError('http_request_invalid', 400)
        return values[0] if values else None

    def _bearer(self):
        value = self._header('Authorization')
        if not isinstance(value, str) or not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43}', value):
            raise AccessError('authentication_required')
        if getattr(self, '_audit_request', None) is not None:
            try:
                self._audit_operator = self.server.service.auth.operator_id(value[7:])
            except AccessError:
                pass
        return value[7:]

    def _authorize(self, token, assessment):
        operator = self.server.service.auth.require(token, assessment)
        if getattr(self, '_audit_request', None) is not None:
            self._audit_operator = operator; self._audit_assessment = assessment

    def _path(self):
        if (len(self.path) > 2048 or self._header('Transfer-Encoding') is not None
                or self._header('Expect') is not None):
            raise AccessError('http_request_invalid', 400)
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise AccessError('http_request_invalid', 400)
        return parsed

    def _empty_body(self):
        if self._header('Content-Length') not in (None, '0'):
            raise AccessError('http_request_invalid', 400)

    def _login_json(self):
        length = self._header('Content-Length')
        if self._header('Content-Type') != 'application/json' or not length or not re.fullmatch(r'[1-9][0-9]{0,3}', length):
            raise AccessError('http_request_invalid', 400)
        size = int(length)
        if size > MAX_BODY:
            raise AccessError('http_request_invalid', 400)
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise AccessError('http_request_invalid', 400)
        try:
            doc = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError):
            raise AccessError('http_request_invalid', 400) from None
        if not isinstance(doc, dict) or set(doc) != {'username', 'password'}:
            raise AccessError('http_request_invalid', 400)
        return doc

    def _dispatch(self, method):
        try:
            path = self._path()
            if method == 'POST' and path.path == '/api/v1/operator/session':
                if path.query:
                    raise AccessError('http_request_invalid', 400)
                doc = self._login_json()
                result = self.server.service.auth.login(doc['username'], doc['password'])
                if getattr(self, '_audit_request', None) is not None:
                    self._audit_operator = result['operator_id']
                self._send(201, result)
                return
            self._empty_body()
            if method == 'GET' and path.path == '/healthz' and not path.query:
                self._send(200, dict(status='ok', version=VERSION, authentication_mode='local_operator',
                                     report_access='explicit_assessment_grants'))
                return
            if method == 'DELETE' and path.path == '/api/v1/operator/session' and not path.query:
                self.server.service.auth.logout(self._bearer())
                self._send(200, dict(status='logged_out'))
                return
            match = REPORT_PATH.fullmatch(path.path)
            if method != 'GET' or match is None:
                raise AccessError('route_not_found', 404)
            token = self._bearer(); assessment = match[1]
            self._authorize(token, assessment)
            try:
                # An exactly empty query uses defaults on every supported parser.
                pairs = parse_qsl(path.query, keep_blank_values=True, strict_parsing=True, max_num_fields=4) if path.query else []
                values = dict(pairs)
                if len(values) != len(pairs) or set(values) - {'after_analysis_id', 'after_ordinal', 'limit', 'expected_scope_sha256'}:
                    raise ValueError('invalid query')
                if any(not re.fullmatch(r'-?[0-9]{1,4}', values[k]) for k in ('after_ordinal', 'limit') if k in values):
                    raise ValueError('invalid integer')
                params = dict(after_analysis_id=values.get('after_analysis_id', ''),
                    after_ordinal=int(values.get('after_ordinal', '-1')), limit=int(values.get('limit', '100')),
                    expected_scope_sha256=values.get('expected_scope_sha256'))
            except ValueError:
                raise AccessError('report_input_invalid', 400) from None
            result = self.server.service.read_report(token, assessment, **params)
            self._send(404 if result['status'] == 'not_found' else 200, result)
        except AccessError as exc:
            self._send(exc.status, dict(status='failed', error_code=str(exc)))
        except report.pg.PersistenceError as exc:
            code = str(exc) if str(exc) in report.ERRORS else 'database_failed'
            status = 400 if code == 'report_input_invalid' else 409 if code == 'report_scope_conflict' else 503
            self._send(status, dict(status='failed', error_code=code))
        except Exception:
            self._send(503, dict(status='failed', error_code='operator_request_failed'))

    def _serve(self, method):
        sink = self.server.audit
        if sink is None:
            self._dispatch(method)
            return
        self._audit_request = None; self._audit_operator = None
        self._audit_assessment = None; self._audit_http_status = None
        self._audit_delivery_failed = False
        try:
            self._audit_request = sink.begin(audit.operation(method, self.path))
        except audit.AuditError:
            self._send(503, dict(status='failed', error_code='operator_audit_unavailable'))
            return
        outcome = 'response_written'
        try:
            self._dispatch(method)
            if self._audit_delivery_failed: outcome = 'delivery_failed'
            elif self._audit_http_status is None: outcome = 'handler_failed'
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            outcome = 'delivery_failed'; self.close_connection = True
        except Exception:
            outcome = 'handler_failed'; self.close_connection = True
        finally:
            try:
                sink.finish(self._audit_request, http_status=self._audit_http_status, outcome=outcome,
                            operator_id=self._audit_operator, assessment_id=self._audit_assessment)
            except audit.AuditError:
                self.close_connection = True

    def do_GET(self):
        self._serve('GET')

    def do_POST(self):
        self._serve('POST')

    def do_DELETE(self):
        self._serve('DELETE')


def create_server(policy_path, host='127.0.0.1', port=8878, *, tls_cert=None, tls_key=None,
                  audit_path=None, audit_listener='api'):
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError('invalid operator port')
    address = ipaddress.ip_address(host)
    tls = tls_cert is not None and tls_key is not None
    if bool(tls_cert) != bool(tls_key) or (not tls and str(address) != '127.0.0.1') or address.version != 4:
        raise ValueError('remote operator access requires TLS and IPv4')
    context = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(tls_cert, tls_key)
    service = OperatorService(LocalAuth(load_policy(policy_path)))
    server = OperatorServer((str(address), port), service)
    try:
        if audit_path is not None:
            server.audit = audit.FileAudit(audit_path, audit_listener)
        if context:
            # Handshake in get_request would block the accept loop; wrap per worker.
            server.tls_context = context
        return server
    except Exception:
        server.server_close()
        raise


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã local operator report API ' + VERSION)
    parser.add_argument('--accounts', required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8878)
    parser.add_argument('--tls-cert'); parser.add_argument('--tls-key')
    parser.add_argument('--audit-file')
    args = parser.parse_args(argv)
    try:
        with create_server(args.accounts, args.host, args.port, tls_cert=args.tls_cert, tls_key=args.tls_key,
                           audit_path=args.audit_file) as server:
            print(json.dumps(dict(status='listening', version=VERSION)), flush=True)
            server.serve_forever()
        return 0
    except KeyboardInterrupt:
        return 0
    except audit.AuditError:
        print(json.dumps(dict(status='failed', error_code='operator_audit_unavailable')))
        return 2
    except Exception:
        print(json.dumps(dict(status='failed', error_code='operator_startup_failed')))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
