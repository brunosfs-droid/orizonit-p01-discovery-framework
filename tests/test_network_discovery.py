import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / 'network_discovery' / 'P01_Network_Discovery_Scanner.py'
spec = importlib.util.spec_from_file_location('p01_network_discovery', MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ScopeTests(unittest.TestCase):
    def test_cidr_and_exclusion(self):
        scope, excluded = mod.resolve_scope(['192.168.10.0/30'], ['192.168.10.2'])
        self.assertEqual(scope, ['192.168.10.1'])
        self.assertEqual(excluded, ['192.168.10.2'])

    def test_shorthand_range(self):
        values = [str(x) for x in mod.expand_ipv4_expression('192.168.1.10-12')]
        self.assertEqual(values, ['192.168.1.10', '192.168.1.11', '192.168.1.12'])

    def test_port_profile(self):
        safe = mod.parse_ports(None, 'safe')
        standard = mod.parse_ports(None, 'standard')
        self.assertIn(445, safe)
        self.assertIn(8291, standard)
        self.assertGreater(len(standard), len(safe))


class ClassificationTests(unittest.TestCase):
    def test_windows_classification(self):
        device, os_guess, confidence, evidence = mod.classify_asset(
            '192.168.1.10', 'pc01', {135, 445, 3389}, [], [], {'default_gateways': []}
        )
        self.assertEqual(device, 'Windows Host')
        self.assertEqual(os_guess, 'Windows')
        self.assertEqual(confidence, 'High')
        self.assertTrue(evidence)

    def test_printer_classification(self):
        device, _, confidence, _ = mod.classify_asset(
            '192.168.1.50', None, {9100}, [], [], {'default_gateways': []}
        )
        self.assertEqual(device, 'Printer')
        self.assertEqual(confidence, 'High')

    def test_gateway_classification(self):
        device, _, confidence, _ = mod.classify_asset(
            '192.168.1.1', None, {80, 443}, [], [], {'default_gateways': ['192.168.1.1']}
        )
        self.assertEqual(device, 'Router/Gateway')
        self.assertEqual(confidence, 'High')


if __name__ == '__main__':
    unittest.main()
