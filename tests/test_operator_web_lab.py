"""Manual LAB launcher: environment boundary and private temporary cleanup."""
import importlib.util
import io
import json
import os
from pathlib import Path
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch

import test_operator_auth as fixture

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('operator_web_lab', ROOT / 'docs/validation/LOCAL_OPERATOR_WEB_LAB_R1_v0.6.12.py')
lab = importlib.util.module_from_spec(spec); spec.loader.exec_module(lab)


class OperatorWebLabTests(unittest.TestCase):
    LAB = lab
    MANUAL_GATE = 'manual_separate_gate'
    QUALIFIED_WEB_VERSION = '0.6.12'

    def test_wrong_database_host_or_ci_flag_fails_before_db_password_and_listener(self):
        lab = self.LAB
        for database, host, flag in [('canca_ci', '127.0.0.1', ''), ('canca_p01_restore_r1', '192.0.2.1', ''),
                ('canca_p01_restore_r1', '127.0.0.1', '1')]:
            with patch.dict(os.environ, {'PGDATABASE':database, 'PGHOST':host, 'CANCA_TEST_POSTGRES':flag}), \
                    patch.object(lab.lab, 'snapshot') as snapshot, patch.object(lab.getpass, 'getpass') as prompt, \
                    patch.object(lab.web, 'create_server') as create, redirect_stdout(io.StringIO()):
                self.assertEqual(lab.cli(), 2)
            snapshot.assert_not_called(); prompt.assert_not_called(); create.assert_not_called()

    def test_temporary_policy_removed_after_stop_even_when_database_changes(self):
        lab = self.LAB
        for changed in (False, True):
            observed = []
            # Mocked listeners identify the historical pinned package, not future HEAD.
            with patch.object(lab.web, 'VERSION', self.QUALIFIED_WEB_VERSION), \
                    patch.dict(os.environ, {'PGDATABASE':'canca_p01_restore_r1', 'PGHOST':'127.0.0.1', 'CANCA_TEST_POSTGRES':''}), \
                    patch.object(lab.lab, 'snapshot', side_effect=[{'before':1}, {'before':2 if changed else 1}]), \
                    patch.object(lab.getpass, 'getpass', return_value=fixture.PASSWORD), \
                    patch.object(lab.web, 'create_server') as create, redirect_stdout(io.StringIO()) as output:
                def startup(policy, port):
                    observed.append(policy)
                    doc = json.loads(policy.read_text())
                    self.assertNotIn(fixture.PASSWORD, policy.read_text())
                    self.assertEqual(doc['accounts'][0]['grants'][0]['assessment_id'], 'P01-PG-LAB-R1')
                    if os.name == 'posix': self.assertEqual(policy.stat().st_mode & 0o777, 0o600)
                    server = __import__('unittest.mock', fromlist=['MagicMock']).MagicMock()
                    server.__enter__.return_value = server
                    server.serve_forever.side_effect = KeyboardInterrupt
                    return server
                create.side_effect = startup
                self.assertEqual(lab.cli(), 2 if changed else 0)
                self.assertNotIn(fixture.PASSWORD, output.getvalue())
                if not changed: self.assertIn(self.MANUAL_GATE, output.getvalue())
            self.assertEqual(len(observed), 1); self.assertFalse(observed[0].parent.exists())


export_spec=importlib.util.spec_from_file_location('operator_web_export_lab',
    ROOT/'docs/validation/LOCAL_OPERATOR_WEB_EXPORT_LAB_R1_v0.6.13.py')
export_lab=importlib.util.module_from_spec(export_spec); export_spec.loader.exec_module(export_lab)


class OperatorWebExportLabTests(OperatorWebLabTests):
    LAB = export_lab
    MANUAL_GATE = 'manual_download_separate_gate'
    QUALIFIED_WEB_VERSION = '0.6.13'

    def test_wrong_web_revision_fails_before_snapshot_password_and_listener(self):
        lab=self.LAB
        for version in ('0.6.12', '0.6.15'):
            with patch.object(lab.web,'VERSION',version), patch.object(lab.lab,'snapshot') as snapshot, \
                    patch.object(lab.getpass,'getpass') as prompt, redirect_stdout(io.StringIO()):
                self.assertEqual(lab.cli(),2)
            snapshot.assert_not_called(); prompt.assert_not_called()


if __name__ == '__main__': unittest.main()
