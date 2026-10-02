import os
import unittest
from unittest.mock import patch
import postgres_backup_restore_smoke as smoke


class BackupGuardTests(unittest.TestCase):
    def test_rejects_non_ci_before_connection_and_subprocess(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(smoke.pg, 'open_connection') as conn, \
                patch.object(smoke.subprocess, 'run') as command:
            self.assertEqual(smoke.cli(['--postgres-container', 'a' * 64]), 2)
            conn.assert_not_called()
            command.assert_not_called()

    def test_rejects_lab_database_and_container_argument(self):
        env = dict(GITHUB_ACTIONS='true', CANCA_TEST_POSTGRES='1', PGDATABASE='canca_ci',
                   PGUSER='canca_ci', PGHOST='127.0.0.1', PGPORT='5432')
        with patch.dict(os.environ, env, clear=True):
            smoke.guard('a' * 64)
            for key, value in [('PGDATABASE', 'canca_p01_lab_r1'), ('PGHOST', '192.0.2.1'),
                               ('PGUSER', 'postgres'), ('PGSERVICE', 'lab')]:
                with self.subTest(key=key), patch.dict(os.environ, {key: value}):
                    with self.assertRaises(smoke.SmokeError):
                        smoke.guard('a' * 64)
            with self.assertRaises(smoke.SmokeError):
                smoke.guard('--privileged')
