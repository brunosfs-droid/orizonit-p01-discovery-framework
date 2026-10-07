"""CI-only destructive harness must reject before connection, Docker or fixtures."""
import os
import unittest
from unittest.mock import patch
import workspace_backup_restore_smoke as smoke

class WorkspaceBackupGuardTests(unittest.TestCase):
    def test_non_ci_environment_never_connects_or_creates_fixture(self):
        with patch.dict(os.environ,{},clear=True),patch.object(smoke.pg,'open_connection') as connect,patch.object(smoke,'docker') as docker:
            with self.assertRaises(smoke.SmokeError):smoke.run('a'*64)
            connect.assert_not_called();docker.assert_not_called()
