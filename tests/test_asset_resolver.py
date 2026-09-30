import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
path = ROOT / "asset_resolver" / "P01_Asset_Resolver.py"
spec = importlib.util.spec_from_file_location("p01_asset_resolver", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def write_json(path, payload, sidecar=False):
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if sidecar:
        digest = mod.digest_file(path)
        path.with_suffix(path.suffix + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return path


def network_doc():
    assets = [
        ("192.168.100.10", "P01-DC01.p01.lab.test", "00:11:22:33:44:10", "Windows Host", "Windows"),
        ("192.168.100.20", "P01-MGMT01", "00:11:22:33:44:20", "Windows Host", "Windows"),
        ("192.168.100.30", "P01-W11-01.p01.lab.test", "00:11:22:33:44:30", "Windows Host", "Windows"),
        ("192.168.100.40", "P01-LNX-UBU01.p01.lab.test", "00:11:22:33:44:40", "Linux/Unix Host", "Linux/Unix-like"),
        ("192.168.100.50", "P01-LNX-RKY01.p01.lab.test", "00:11:22:33:44:50", "Linux/Unix Host", "Linux/Unix-like"),
    ]
    return {
        "metadata": {
            "scanner_name": "P01-Network-Discovery-Scanner",
            "scanner_version": "0.4.1",
            "run_label": "P01LAB-NODE-W11-WINRM-R2",
        },
        "assets": [
            {
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "device_type_guess": device,
                "os_guess": os_guess,
                "confidence": "High" if "Windows" in device else "Medium",
                "open_ports": [{"port": 5985, "protocol": "tcp", "service": "winrm-http"}]
                if "Windows" in device else [{"port": 22, "protocol": "tcp", "service": "ssh"}],
            }
            for ip, hostname, mac, device, os_guess in assets
        ],
    }


def windows_target(ip, hostname, fqdn, role, serial):
    return {
        "metadata": {
            "executor_name": "P01-Credentialed-Discovery-Executor",
            "executor_version": "0.4b.5",
            "run_label": "P01LAB-MULTI-FULL-R1",
            "secret_values_persisted_to_output": False,
        },
        "action": {
            "target_ip": ip,
            "hostname": hostname,
            "device_type": "Windows Host",
            "os_family": "Windows",
            "realm": "P01LAB",
            "protocol": "winrm",
            "port": 5985,
        },
        "authentication": {"success": True},
        "enrichment": {
            "collection_status": "collected",
            "identity": {
                "computer_name": hostname.split(".", 1)[0],
                "fqdn": fqdn,
                "serial_number": serial,
                "domain": "p01.lab.test",
                "part_of_domain": True,
                "domain_role": role,
            },
            "operating_system": {
                "caption": "Microsoft Windows",
                "build_number": "20348",
            },
            "network": {
                "interfaces": [{
                    "interface_alias": "Ethernet",
                    "ipv4": [{"address": ip, "prefix_length": 24}],
                }],
            },
        },
        "circuit_after_attempt": {"circuit_open": False},
    }


def linux_target(ip, hostname, fingerprint):
    return {
        "metadata": {
            "executor_name": "P01-Credentialed-Discovery-Executor",
            "executor_version": "0.4b.5",
            "run_label": "P01LAB-MULTI-FULL-R1",
            "secret_values_persisted_to_output": False,
        },
        "action": {
            "target_ip": ip,
            "hostname": hostname,
            "device_type": "Linux/Unix Host",
            "os_family": "Linux/Unix-like",
            "realm": "P01LAB",
            "protocol": "ssh",
            "port": 22,
        },
        "authentication": {
            "success": True,
            "server_host_key": {
                "algorithm": "ssh-ed25519",
                "fingerprint_sha256": fingerprint,
            },
        },
        "enrichment": {
            "collection_status": "collected",
            "identity": {
                "hostname": hostname.split(".", 1)[0],
                "kernel": "Linux",
            },
            "network": {
                "interfaces": [{
                    "name": "eth0",
                    "ipv4": [{"address": ip, "prefix_length": 24}],
                }],
            },
        },
        "circuit_after_attempt": {"circuit_open": False},
    }


def manifest_doc():
    return {
        "schema_version": "0.4b.6",
        "assessment_id": "P01LAB-CTX-R1",
        "authorized_scopes": ["192.168.100.0/24"],
        "domains": [{
            "dns_domain": "p01.lab.test",
            "netbios_name": "P01LAB",
            "forest": "p01.lab.test",
            "scopes": ["192.168.100.0/24"],
            "evidence_state": "declared",
        }],
        "allowed_protocols": ["ssh", "winrm"],
        "safety_policy": {
            "default_concurrency": 1,
            "max_actions": 25,
            "require_authorized_ack": True,
            "auto_expand_scope": False,
        },
    }


class AssetResolverTests(unittest.TestCase):
    def _lab(self, td):
        td = pathlib.Path(td)
        network = write_json(td / "network.json", network_doc(), sidecar=True)
        evidence = [
            write_json(td / "dc.json", windows_target("192.168.100.10", "P01-DC01", "P01-DC01.p01.lab.test", 5, "DC-SERIAL"), sidecar=True),
            write_json(td / "mgmt.json", windows_target("192.168.100.20", "P01-MGMT01", "P01-MGMT01.p01.lab.test", 3, "MGMT-SERIAL"), sidecar=True),
            write_json(td / "w11.json", windows_target("192.168.100.30", "P01-W11-01", "P01-W11-01.p01.lab.test", 1, "W11-SERIAL"), sidecar=True),
            write_json(td / "ubu.json", linux_target("192.168.100.40", "P01-LNX-UBU01.p01.lab.test", "SHA256:ubuntu"), sidecar=True),
            write_json(td / "rky.json", linux_target("192.168.100.50", "P01-LNX-RKY01.p01.lab.test", "SHA256:rocky"), sidecar=True),
        ]
        manifest = write_json(td / "manifest.json", manifest_doc(), sidecar=False)
        return network, evidence, manifest

    def test_five_lab_assets_resolve_to_five(self):
        with tempfile.TemporaryDirectory() as td:
            network, evidence, manifest = self._lab(td)
            result = mod.resolve(network, evidence, manifest, require_evidence_sidecars=True)
            self.assertEqual(result["summary"]["network_assets_seen"], 5)
            self.assertEqual(result["summary"]["credentialed_observations_seen"], 5)
            self.assertEqual(result["summary"]["logical_assets_resolved"], 5)
            self.assertEqual(result["summary"]["unresolved_observations"], 0)
            self.assertEqual(result["summary"]["ambiguous_correlations"], 0)
            self.assertTrue(all(len(a["sources"]) >= 2 for a in result["assets"]))

    def test_ip_alone_never_auto_merges(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            n = network_doc()
            n["assets"] = [{
                "ip": "192.168.100.30",
                "hostname": "alpha.example.test",
                "mac": "00:11:22:33:44:30",
                "device_type_guess": "Windows Host",
                "os_guess": "Windows",
                "confidence": "High",
                "open_ports": [{"port": 5985, "protocol": "tcp", "service": "winrm-http"}],
            }]
            network = write_json(td / "network.json", n)
            bad = windows_target("192.168.100.30", "BETA", None, 1, "")
            bad["enrichment"]["identity"]["domain"] = ""
            bad["enrichment"]["identity"]["part_of_domain"] = False
            evidence = write_json(td / "bad.json", bad)
            result = mod.resolve(network, [evidence])
            self.assertEqual(result["summary"]["logical_assets_resolved"], 2)
            self.assertEqual(result["summary"]["unresolved_observations"], 1)

    def test_fqdn_without_network_corroboration_does_not_merge(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            n = network_doc()
            n["assets"] = [n["assets"][2]]
            network = write_json(td / "network.json", n)
            evidence_doc = windows_target("192.168.100.99", "P01-W11-01", "P01-W11-01.p01.lab.test", 1, "")
            evidence = write_json(td / "w11-other-ip.json", evidence_doc)
            result = mod.resolve(network, [evidence])
            self.assertEqual(result["summary"]["logical_assets_resolved"], 2)
            self.assertEqual(result["summary"]["unresolved_observations"], 1)

    def test_hostname_plus_ip_merges(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            n = network_doc()
            n["assets"] = [n["assets"][1]]
            network = write_json(td / "network.json", n)
            evidence = write_json(td / "mgmt.json", windows_target("192.168.100.20", "P01-MGMT01", None, 3, ""))
            result = mod.resolve(network, [evidence])
            self.assertEqual(result["summary"]["logical_assets_resolved"], 1)
            self.assertEqual(result["summary"]["correlated_observations"], 1)

    def test_same_mac_network_observations_are_not_premerged(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            n = network_doc()
            n["assets"] = [
                {
                    "ip": "192.168.100.7",
                    "hostname": "alpha.example.test",
                    "mac": "00:aa:bb:cc:dd:ee",
                    "device_type_guess": "Unknown",
                    "os_guess": None,
                    "confidence": "Low",
                    "open_ports": [],
                },
                {
                    "ip": "192.168.100.102",
                    "hostname": "beta.example.test",
                    "mac": "00:aa:bb:cc:dd:ee",
                    "device_type_guess": "Unknown",
                    "os_guess": None,
                    "confidence": "Low",
                    "open_ports": [],
                },
            ]
            network = write_json(td / "network.json", n)
            dummy = write_json(td / "dummy.json", linux_target("192.168.100.40", "unrelated.example.test", "SHA256:x"))
            result = mod.resolve(network, [dummy])
            network_assets = [a for a in result["assets"] if any(s["source_kind"] == "network_discovery" for s in a["sources"])]
            self.assertEqual(len(network_assets), 2)

    def test_manifest_observed_realm_not_membership_confirmation(self):
        with tempfile.TemporaryDirectory() as td:
            network, evidence, manifest = self._lab(td)
            result = mod.resolve(network, evidence, manifest)
            linux_asset = next(a for a in result["assets"] if "192.168.100.40" in a["addresses"])
            self.assertEqual(linux_asset["identity"]["realm_evidence_state"], "observed")
            windows_asset = next(a for a in result["assets"] if "192.168.100.30" in a["addresses"])
            self.assertEqual(windows_asset["identity"]["realm_evidence_state"], "credentialed_confirmed")

    def test_local_auth_realm_does_not_override_directory_realm(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            n = network_doc()
            n["assets"] = [n["assets"][1]]
            network = write_json(td / "network.json", n)
            mgmt = windows_target(
                "192.168.100.20",
                "P01-MGMT01",
                "P01-MGMT01.p01.lab.test",
                3,
                "MGMT-SERIAL",
            )
            mgmt["action"]["realm"] = "local"
            evidence = write_json(td / "mgmt.json", mgmt)
            manifest = write_json(td / "manifest.json", manifest_doc())
            result = mod.resolve(network, [evidence], manifest)
            asset = result["assets"][0]
            self.assertEqual(asset["identity"]["authentication_realm"], "local")
            self.assertEqual(asset["identity"]["realm_name"], "P01LAB")
            self.assertEqual(asset["identity"]["realm_dns_domain"], "p01.lab.test")
            self.assertEqual(asset["identity"]["realm_evidence_state"], "credentialed_confirmed")
            self.assertFalse(any(x["field"] == "realm_name" for x in asset["conflicts"]))

    def test_realm_evidence_progression_is_not_conflict(self):
        claims = [
            mod.field_claim("realm_evidence_state", "observed", "src-a", "observed", "manifest"),
            mod.field_claim("realm_evidence_state", "credentialed_confirmed", "src-b", "credentialed_confirmed", "winrm"),
        ]
        resolved, _, conflicts = mod.choose_claims(claims)
        self.assertEqual(resolved["realm_evidence_state"], "credentialed_confirmed")
        self.assertEqual(conflicts, [])

    def test_windows_device_class_refinement_is_not_conflict(self):
        claims = [
            mod.field_claim("device_class", "Windows Host", "src-a", "medium", "network"),
            mod.field_claim("device_class", "Domain Controller", "src-b", "credentialed_confirmed", "winrm"),
        ]
        resolved, _, conflicts = mod.choose_claims(claims)
        self.assertEqual(resolved["device_class"], "Domain Controller")
        self.assertEqual(conflicts, [])

    def test_conflicts_are_preserved(self):
        claims = [
            mod.field_claim("os_family", "Windows", "src-a", "medium", "a"),
            mod.field_claim("os_family", "Linux", "src-b", "medium", "b"),
        ]
        resolved, provenance, conflicts = mod.choose_claims(claims)
        self.assertIn(resolved["os_family"], {"Windows", "Linux"})
        self.assertEqual(len(provenance["os_family"]), 2)
        self.assertEqual(conflicts[0]["field"], "os_family")

    def test_asset_ids_deterministic_for_same_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            network, evidence, manifest = self._lab(td)
            first = mod.resolve(network, evidence, manifest)
            second = mod.resolve(network, list(reversed(evidence)), manifest)
            self.assertEqual(
                [a["asset_id"] for a in first["assets"]],
                [a["asset_id"] for a in second["assets"]],
            )

    def test_output_has_no_secret_provider_reference(self):
        with tempfile.TemporaryDirectory() as td:
            network, evidence, manifest = self._lab(td)
            result = mod.resolve(network, evidence, manifest)
            rendered = json.dumps(result)
            self.assertNotIn("wincred://", rendered)
            self.assertNotIn("prompt://", rendered)
            self.assertNotIn("secret_refs", rendered)
            mod.assert_no_secret_material(result)

    def test_require_sidecars(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            network = write_json(td / "network.json", network_doc(), sidecar=True)
            evidence = write_json(td / "w11.json", windows_target("192.168.100.30", "P01-W11-01", "P01-W11-01.p01.lab.test", 1, "W11"), sidecar=False)
            with self.assertRaises(ValueError):
                mod.resolve(network, [evidence], require_evidence_sidecars=True)


if __name__ == "__main__":
    unittest.main()
