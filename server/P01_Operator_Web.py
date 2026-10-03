#!/usr/bin/env python3
"""Small same-origin Web client of the qualified read-only operator API."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import P01_Operator_API as api
import P01_Operator_Export as exports

VERSION = '0.6.13'
EXPORT_PATH = re.compile(r'/api/v1/assessments/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/report/export')
ASSETS = {'/': ('index.html', 'text/html; charset=utf-8'),
          '/assets/operator.css': ('operator.css', 'text/css; charset=utf-8'),
          '/assets/operator.js': ('operator.js', 'text/javascript; charset=utf-8')}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")


class WebHandler(api.OperatorHandler):
    server_version = 'CancaOperatorWeb/' + VERSION

    def _browser_origin(self):
        # Direct IPv4 endpoint (or localhost for an SSH tunnel); no forwarded trust.
        host = self._header('Host')
        if not host or any(c in host for c in '/\\@?# \t\r\n'):
            raise api.AccessError('http_request_invalid', 400)
        try:
            authority = urlsplit('http://' + host)
            name = authority.hostname
            port = authority.port or (443 if getattr(self.server, 'tls_context', None) else 80)
            bound = self.server.server_address[0]
            if port != self.server.server_port:
                raise ValueError('wrong port')
            if bound == '127.0.0.1':
                if name not in ('127.0.0.1', 'localhost'):
                    raise ValueError('wrong host')
            else:
                address = ipaddress.ip_address(name)
                if address.version != 4 or (bound != '0.0.0.0' and str(address) != bound):
                    raise ValueError('wrong host')
        except (ValueError, TypeError):
            raise api.AccessError('http_request_invalid', 400) from None
        scheme = 'https' if getattr(self.server, 'tls_context', None) else 'http'
        origin = self._header('Origin')
        if origin is not None and origin != scheme + '://' + host:
            raise api.AccessError('browser_origin_denied', 403)
        if self._header('Sec-Fetch-Site') not in (None, 'none', 'same-origin'):
            raise api.AccessError('browser_origin_denied', 403)

    def _asset(self, raw, content_type):
        self.send_response(200)
        self._asset_headers(raw, content_type)
        self.wfile.write(raw)

    def _asset_headers(self, raw, content_type):
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', CSP)
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Connection', 'close')
        self.close_connection = True
        self.end_headers()

    def _dispatch(self, method):
        try:
            self._browser_origin()
            path = self._path()
            match = EXPORT_PATH.fullmatch(path.path)
            if match is not None and method == 'GET':
                self._empty_body()
                token = self._bearer(); assessment = match[1]
                self.server.service.auth.require(token, assessment)
                try:
                    pairs = parse_qsl(path.query, keep_blank_values=True, strict_parsing=True, max_num_fields=2)
                    values = dict(pairs)
                    if (len(values) != len(pairs) or 'expected_scope_sha256' not in values
                            or set(values) - {'expected_scope_sha256', 'limit'}
                            or not re.fullmatch(r'[1-9][0-9]{0,2}', values.get('limit', '100'))):
                        raise ValueError('invalid export query')
                    scope = values['expected_scope_sha256']; limit = int(values.get('limit', '100'))
                    api.report.validate_query(assessment, limit=limit, expected_scope_sha256=scope)
                except (ValueError, api.report.pg.PersistenceError):
                    raise api.AccessError('report_input_invalid', 400) from None
                with self.server.report_exports.build(token, assessment, scope, limit) as (raw, checksum):
                    self.send_response(200)
                    self.send_header('Content-Disposition', 'attachment; filename="canca-' + assessment + '-report.zip"')
                    self.send_header('X-Canca-Report-Scope-SHA256', scope)
                    self.send_header('X-Canca-Export-SHA256', checksum)
                    self._asset_headers(raw, 'application/zip')
                    self.wfile.write(raw)
                return
            if method == 'GET' and path.path in ASSETS:
                self._empty_body()
                if path.query:
                    raise api.AccessError('http_request_invalid', 400)
                self._asset(*self.server.web_assets[path.path])
                return
            if method == 'GET' and path.path == '/healthz' and not path.query:
                self._empty_body()
                self._send(200, dict(status='ok', version=api.VERSION, web_version=VERSION,
                    authentication_mode='local_operator', report_access='explicit_assessment_grants'))
                return
        except api.AccessError as exc:
            self._send(exc.status, dict(status='failed', error_code=str(exc)))
            return
        except api.report.pg.PersistenceError as exc:
            code = str(exc) if str(exc) in exports.export.ERRORS else 'database_failed'
            status = (404 if code == 'assessment_not_found' else 409 if code == 'report_scope_conflict'
                      else 413 if code == 'export_limit_exceeded' else 503)
            self._send(status, dict(status='failed', error_code=code))
            return
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
            return
        except Exception:
            self._send(503, dict(status='failed', error_code='operator_request_failed'))
            return
        super()._dispatch(method)


def create_server(policy_path, host='127.0.0.1', port=8878, *, tls_cert=None, tls_key=None):
    directory = Path(__file__).resolve().parent / 'web'
    assets = {}
    for route, (name, content_type) in ASSETS.items():
        path = directory / name
        if path.resolve() != path or not path.is_file() or not 0 < path.stat().st_size <= 65536:
            raise ValueError('invalid Web asset')
        raw = path.read_bytes()
        if not 0 < len(raw) <= 65536:
            raise ValueError('invalid Web asset')
        raw.decode('utf-8')
        assets[route] = (raw, content_type)
    server = api.create_server(policy_path, host, port, tls_cert=tls_cert, tls_key=tls_key)
    server.web_assets = assets
    server.report_exports = exports.ExportDelivery(server.service.auth)
    server.RequestHandlerClass = WebHandler
    return server


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Cancã operator Web ' + VERSION)
    parser.add_argument('--accounts', required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8878)
    parser.add_argument('--tls-cert'); parser.add_argument('--tls-key')
    args = parser.parse_args(argv)
    try:
        with create_server(args.accounts, args.host, args.port, tls_cert=args.tls_cert, tls_key=args.tls_key) as server:
            print(json.dumps(dict(status='listening', web_version=VERSION, api_version=api.VERSION)), flush=True)
            server.serve_forever()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        print(json.dumps(dict(status='failed', error_code='operator_web_startup_failed')))
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
