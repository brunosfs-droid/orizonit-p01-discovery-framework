#!/usr/bin/env python3
"""Temporary new Web download gate; SELECT-only before/after invariant."""
from __future__ import annotations
import getpass
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'server'))
import P01_Operator_Web as web
import P01_Operator_Auth as auth
spec = importlib.util.spec_from_file_location('operator_lab_boundary',
    Path(__file__).with_name('LOCAL_OPERATOR_LAB_R1_v0.6.11.py'))
lab = importlib.util.module_from_spec(spec); spec.loader.exec_module(lab)


def run():
    lab.require(web.VERSION == "0.6.13")
    lab.require(os.environ.get('PGDATABASE') == lab.DATABASE
        and os.environ.get('PGHOST') in {'127.0.0.1', 'localhost'}
        and os.environ.get('CANCA_TEST_POSTGRES') != '1')
    before = lab.snapshot(lab.DATABASE)
    password = getpass.getpass('Nova senha SINTETICA para reader-export (15–256 caracteres): ')
    confirmation = getpass.getpass('Repita a senha sintetica: ')
    lab.require(password == confirmation)
    with tempfile.TemporaryDirectory(prefix='canca-operator-web-export-r1-') as temporary:
        policy = Path(temporary) / 'accounts.json'
        auth.create_policy(policy, 'OP-WEB-EXPORT-R1', 'reader-export', [lab.ASSESSMENT], password)
        password = confirmation = None
        with web.create_server(policy, port=8878) as server:
            print(json.dumps(dict(status='OPERATOR WEB EXPORT LAB READY', web_version=web.VERSION,
                url='http://127.0.0.1:8878/', username='reader-export', assessment_id=lab.ASSESSMENT,
                database_writes=False, stop='Ctrl+C depois de sair no navegador')), flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    lab.require(lab.snapshot(lab.DATABASE) == before)
    return dict(status='OPERATOR WEB EXPORT LAB STOP PASS', web_version=web.VERSION,
        tables_compared=len(lab.TABLES), database_mutated=False, store_accessed=False,
        temporary_server_stopped=True, temporary_credentials_removed=True,
        browser_acceptance='manual_download_separate_gate')


def cli():
    try:
        print(json.dumps(run())); return 0
    except (Exception, KeyboardInterrupt):
        print(json.dumps(dict(status='failed', error_code='operator_web_lab_check_failed'))); return 2


if __name__ == '__main__': raise SystemExit(cli())
