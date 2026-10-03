"""Run event-level client security/navigation checks; graphical LAB is separate."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

NODE = shutil.which('node') or os.environ.get('CODEX_PRIMARY_RUNTIME_NODE')


class OperatorWebClientTests(unittest.TestCase):
    @unittest.skipUnless(NODE and Path(NODE).is_file(), 'Node needed for Web client behavior checks')
    def test_client_login_text_render_fence_logout_expiry_and_late_response(self):
        script = Path(__file__).with_name('operator_web_client.cjs')
        result = subprocess.run([NODE, str(script)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('OPERATOR WEB CLIENT PASS', result.stdout)


if __name__ == '__main__': unittest.main()
