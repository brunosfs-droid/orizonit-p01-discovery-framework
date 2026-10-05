"""SNMP evidence/portable/replay contracts. Live traffic is synthetic IPv4 loopback only."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
for directory in ("credentialed_enrichment", "asset_resolver", "evidence_bundle", "ingestion", "runtime"):
    sys.path.insert(0, str(ROOT / directory))
import P01_SNMP_Evidence as reader
import P01_Asset_Resolver as resolver
import P01_Evidence_Bundle as bundle
import P01_Offline_Import as importer
import P01_Discovery_Node as runtime
from test_snmp_planned_execution import discovery, requests, profiles, build_manifest, assert_private
from test_snmp_enricher import LoopbackAgent, HAS_SNMP, COMMUNITY, AUTH, PRIV

HAS_SCHEMA = importlib.util.find_spec("jsonschema") is not None
if os.environ.get("CANCA_REQUIRE_SNMP_TESTS") == "1" and not HAS_SCHEMA:
    raise RuntimeError("SNMP CI requires the optional schema runtime")


def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(payload, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    path.write_bytes(raw)
    path.with_suffix(path.suffix + ".sha256").write_text(
        f"{hashlib.sha256(raw).hexdigest()}  {path.name}\n", encoding="utf-8")
    return path


def network(*ips, name="synthetic-router"):
    doc = discovery(*(ips or ("127.0.0.1",)))
    doc["metadata"]["scanner_name"] = "P01-Network-Discovery-Scanner"
    for asset in doc["assets"]:
        asset["hostname"] = name
    return doc


def raw_evidence(mode="full", ip="127.0.0.1", name="synthetic-router"):
    values = ["1.3.6.1.4.1.9999.1", "Synthetic Router", 123456, name, "synthetic rack", 72, 4, 1]
    fields = [{"field": field, "oid": oid, "status": "collected", "value": value}
              for (field, oid, _), value in zip(reader.FIELDS, values)]
    maximum, status, success, result, category, attempted = 8, "collected", True, "read_access_confirmed", None, 8
    if mode == "auth_only":
        maximum, fields, status, attempted = 1, fields[:1], "access_probe_only", 1
    elif mode == "dry_run":
        fields, status, success, result, attempted = [], "not_attempted", False, "not_attempted", 0
    elif mode == "failed":
        fields = [{"field": field, "oid": oid, "status": "timeout" if i == 0 else "not_attempted"}
                  for i, (field, oid, _) in enumerate(reader.FIELDS)]
        status, success, result, category, attempted = "not_collected", False, "probe_failed", "transport_or_silent_denial", 1
    elif mode == "partial":
        fields[4].pop("value"); fields[4]["status"] = "not_available"
        status = "collected_with_field_failures"
    return {"metadata": {"enricher_name": reader.ADAPTER_NAME, "enricher_version": "0.4b.7",
                         "schema_version": "0.4b.7", "generated_at_utc": "2026-10-05T11:30:00+00:00",
                         "execution_mode": "dry_run" if mode == "dry_run" else "execute",
                         "read_only_mode": True, "secret_values_persisted_to_output": False},
            "target": {"ip": ip, "port": 1161, "transport": "udp"},
            "credential_policy": {"profile_id": "network-read", "auth_type": "snmpv2c",
                                  "matched_scope": ip + "/32", "attempt_limit": 1,
                                  "same_profile_retries": 0, "context_source": "operator_supplied"},
            "authentication": {"success": success, "result": result, "failure_category": category,
                               "counts_against_credential_budget": False},
            "collection": {"status": status, "fields": fields},
            "summary": {"get_operations_attempted": attempted,
                        "collected_fields": sum(row["status"] == "collected" for row in fields)},
            "limits": {"max_get_operations": maximum, "operation_timeout_seconds": 2.0,
                       "deadline_seconds": 20.0, "max_text_bytes": 1024},
            "warnings": ["snmpv2c_unencrypted_transport"]}


def wrapped(raw=None):
    raw = copy.deepcopy(raw or raw_evidence())
    return {"metadata": {"executor_name": "P01-Credentialed-Discovery-Executor", "executor_version": "0.4b.8",
                         "generated_at_utc": raw["metadata"]["generated_at_utc"], "run_label": "SYNTHETIC-FULL",
                         "read_only_mode": True, "secret_values_persisted_to_output": False,
                         "snmp_extension_version": "0.4b.8", "snmp_execution_enabled": True},
            "action": {"protocol": "snmp", "target_ip": raw["target"]["ip"], "port": raw["target"]["port"],
                       "hostname": "operator-name.synthetic.test", "device_type": "Domain Controller",
                       "os_family": "Windows", "realm": "DECLARED"},
            "authentication": {"profile_id": "network-read", "protocol": "snmp", **raw["authentication"]},
            "enrichment": {"protocol": "snmp", "adapter_name": reader.ADAPTER_NAME, "adapter_version": "0.4b.7",
                           "schema_version": "0.4b.7", "collection_status": raw["collection"]["status"],
                           "fields": raw["collection"]["fields"], "summary": raw["summary"],
                           "limits": raw["limits"], "warnings": raw["warnings"]}}


def managed(root, port=1161, version="snmpv2c"):
    manifest = write_json(root / "assessment.json", build_manifest(
        "SYNTHETIC", "loopback", ["127.0.0.0/8"], [], [], ["snmp"]))
    profile_path = write_json(root / "profiles.json", profiles(version))
    request_path = write_json(root / "requests.json", requests(("127.0.0.1", port, "network-read")))
    workspace = Path(runtime.init_workspace(root / "runs", "SYNTHETIC", "R1", "NODE1", manifest, profile_path)["workspace"])
    seed = write_json(workspace / "evidence" / "network.json", network())
    state = runtime._load_state(workspace)
    state["steps"]["network_discovery"] = {"status": "completed"}
    state["artifacts"]["network_discovery"] = {"path": runtime._relative_if_owned(workspace, seed),
                                              "sha256": runtime.digest_file(seed), "hosts_discovered": 1}
    runtime._write_state(workspace, state)
    runtime.run_credential_plan(workspace, snmp_requests=request_path)
    return workspace, request_path, manifest, profile_path


class EvidenceContracts(unittest.TestCase):
    def test_supported_raw_and_executor_envelopes(self):
        for mode in ("full", "auth_only", "partial", "failed"):
            raw = raw_evidence(mode)
            with self.subTest(mode=mode):
                self.assertEqual(reader.parse(raw), reader.parse(wrapped(raw)))
        self.assertFalse(reader.parse(raw_evidence("dry_run"))["inventory_eligible"])

    def test_exact_field_order_oid_and_coverage(self):
        for mutation in (lambda p: p["collection"]["fields"].reverse(),
                         lambda p: p["collection"]["fields"].pop(),
                         lambda p: p["collection"]["fields"][1].update(oid=reader.FIELDS[0][1]),
                         lambda p: p["collection"]["fields"][1].update(field="sys_object_id"),
                         lambda p: p["summary"].update(collected_fields=7),
                         lambda p: p["summary"].update(get_operations_attempted=0),
                         lambda p: p["collection"].update(status="access_probe_only")):
            doc = raw_evidence(); mutation(doc)
            with self.assertRaisesRegex(ValueError, "^invalid_snmp_evidence_contract$"):
                reader.parse(doc)

    def test_scalar_types_and_bounds(self):
        for index, values in ((0, [True, "1.40.1", "9.1", "1.3.-1", "1.3.4294967296"]),
                              (1, [1, "x" * 1025, "é" * 513, "embedded env://reference"]), (2, [True, -1, 4294967296]),
                              (5, [True, -1, 128]), (6, [False, -1, 2147483648]), (7, [True, 0, 3])):
            for value in values:
                doc = raw_evidence(); doc["collection"]["fields"][index]["value"] = value
                with self.subTest(index=index, value=repr(value)[:20]), self.assertRaises(ValueError):
                    reader.parse(doc)

    def test_missing_and_uncollected_values_fail_closed(self):
        for mutation in (lambda p: p["collection"]["fields"][0].pop("value"),
                         lambda p: p["collection"]["fields"][0].update(status="not_available"),
                         lambda p: p["collection"]["fields"][0].update(extra="unsafe")):
            doc = raw_evidence(); mutation(doc)
            with self.assertRaises(ValueError): reader.parse(doc)

    def test_authentication_and_limit_consistency(self):
        for mutation in (lambda p: p["authentication"].update(success=False),
                         lambda p: p["authentication"].update(counts_against_credential_budget=True),
                         lambda p: p["limits"].update(max_get_operations=True),
                         lambda p: p["limits"].update(deadline_seconds=float("nan")),
                         lambda p: p["metadata"].update(enricher_version="future"),
                         lambda p: p["metadata"].update(execution_mode="dry_run"),
                         lambda p: p["target"].update(port=True), lambda p: p["target"].update(ip="localhost")):
            doc = raw_evidence(); mutation(doc)
            with self.assertRaises(ValueError): reader.parse(doc)

    def test_invalid_recognized_wrapper_never_uses_generic_action_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); seeds = write_json(root / "network.json", network(name="operator-name.synthetic.test"))
            for mutation in (lambda p: p.update(enrichment={}),
                             lambda p: p["enrichment"].update(adapter_version="future"),
                             lambda p: p["metadata"].pop("snmp_execution_enabled")):
                doc = wrapped(); mutation(doc); path = write_json(root / "target.json", doc)
                with self.assertRaises(ValueError): resolver.resolve(seeds, [path])

    def test_dispatch_failure_is_diagnostic_without_invented_coverage(self):
        doc = wrapped(); doc["enrichment"] = None
        doc["authentication"] = {"profile_id": "network-read", "protocol": "snmp", "success": False,
                                 "result": "executor_dispatch_exception", "failure_category": "remote_execution_or_unknown",
                                 "counts_against_credential_budget": False}
        evidence = reader.parse(doc)
        self.assertEqual(evidence["fields"], []); self.assertFalse(evidence["inventory_eligible"])
        self.assertEqual(evidence["mode"], "unknown")

    def test_offline_components_do_not_load_adapters_providers_or_snmp_runtime(self):
        code = '''import sys
from pathlib import Path
root = Path.cwd()
for d in ("asset_resolver", "evidence_bundle", "ingestion"):
    sys.path.insert(0, str(root / d))
import P01_Offline_Import
assert not any(x.startswith(("pysnmp", "P01_Credential_Manager", "P01_SNMP_Enricher")) for x in sys.modules)
'''
        result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


class CorrelationAndReplay(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)

    def resolve(self, docs, seeds=None, manifest=None):
        self.seed = write_json(self.root / "network.json", seeds or network())
        self.targets = [write_json(self.root / f"target-{i}.json", doc) for i, doc in enumerate(docs)]
        self.manifest = write_json(self.root / "assessment.json", manifest) if manifest else None
        return resolver.resolve(self.seed, self.targets, self.manifest, True)

    def package(self, resolved, name="roundtrip"):
        edge = write_json(self.root / (name + "-resolved.json"), resolved)
        path = self.root / (name + ".p01bundle")
        bundle.create_bundle(path, "SYNTHETIC", name, "NODE1", self.seed, self.targets,
                             self.manifest, edge, require_evidence_sidecars=True)
        return path

    def test_full_fields_have_oid_source_hash_observed_strength_and_udp_port(self):
        result = self.resolve([wrapped()]); self.assertEqual(len(result["assets"]), 1)
        asset = result["assets"][0]; self.assertEqual(asset["identifiers"], [])
        for field, oid, _ in reader.FIELDS:
            claim = asset["field_provenance"]["snmp." + field][0]
            self.assertEqual(claim["evidence"], "snmp_get_oid:" + oid)
            self.assertEqual(claim["strength"], "observed")
            self.assertEqual(claim["source_id"], "src-" + resolver.digest_file(self.targets[0])[:16])
        self.assertIn({"port": 1161, "protocol": "udp", "service": "snmp"}, asset["services"])
        self.assertIsNone(asset["identity"]["authentication_realm"])
        self.assertEqual(asset["identity"]["device_class"], "Router/Gateway")

    def test_planned_name_does_not_correlate_ip_alone(self):
        result = self.resolve([wrapped(raw_evidence(name="different-remote-name"))])
        self.assertEqual(len(result["assets"]), 2)
        self.assertEqual(result["summary"]["correlated_observations"], 0)

    def test_name_without_shared_network_evidence_does_not_merge(self):
        result = self.resolve([raw_evidence(ip="127.0.0.2")])
        self.assertEqual(len(result["assets"]), 2)
        self.assertEqual(len({x["asset_id"] for x in result["assets"]}), 2)

    def test_model_and_equal_names_on_distinct_ips_are_not_unique_identifiers(self):
        result = self.resolve([raw_evidence(ip="127.0.0.1"), raw_evidence(ip="127.0.0.2")],
                              network("127.0.0.1", "127.0.0.2", name=None))
        snmp_assets = [x for x in result["assets"] if "snmp.sys_object_id" in x["field_provenance"]]
        self.assertEqual(len(snmp_assets), 2); self.assertTrue(all(not x["identifiers"] for x in snmp_assets))
        self.assertEqual(len({x["asset_id"] for x in result["assets"]}), 4)

    def test_unusable_names_preserve_values_without_identity_promotion(self):
        for name in ("", "<redacted>", "env://reference", "127.0.0.1", "bad name", "unknown"):
            if name.startswith("env://"):
                self.assertIsNone(reader.usable_name(name)); continue
            with self.subTest(name=name):
                result = self.resolve([wrapped(raw_evidence(name=name))])
                asset = next(x for x in result["assets"] if "snmp.sys_name" in x["field_provenance"])
                self.assertIsNone(asset["identity"]["canonical_hostname"])
                self.assertEqual(asset["field_provenance"]["snmp.sys_name"][0]["value"], name)
                self.assertIsNone(asset["identity"]["device_class"])

    def test_auth_dry_run_and_failed_probe_do_not_populate_inventory(self):
        seeds = network(); seeds["assets"] = []
        result = self.resolve([raw_evidence("auth_only"), raw_evidence("dry_run"), wrapped(raw_evidence("failed"))], seeds)
        self.assertEqual(result["assets"], [])
        self.assertEqual(result["summary"]["credentialed_observations_seen"], 0)
        self.assertEqual(result["summary"]["snmp_diagnostic_observations"], 3)
        self.assertTrue(all("new_asset_id" not in item for item in result["unresolved_observations"]))

    def test_partial_fields_and_missing_coverage_survive_roundtrip(self):
        result = self.resolve([raw_evidence("partial")])
        self.assertNotIn("snmp.sys_location", result["assets"][0]["field_provenance"])
        self.assertEqual(result["inputs"]["snmp_evidence"][0]["fields"][4]["status"], "not_available")
        receipt = importer.import_bundle(self.package(result), self.root / "store", process=True, require_outer_sidecar=True)
        self.assertTrue(receipt["semantic_match"])

    def test_duplicate_bytes_are_deduplicated_and_asset_id_is_deterministic(self):
        first = self.resolve([raw_evidence(), raw_evidence()])
        self.assertEqual(first["summary"]["snmp_evidence_seen"], 1)
        self.assertEqual(len(first["assets"][0]["field_provenance"]["snmp.sys_name"]), 1)
        self.assertEqual(first["assets"], resolver.resolve(self.seed, self.targets, None, True)["assets"])

    def test_snmp_suffix_does_not_promote_manifest_realm(self):
        manifest = build_manifest("SYNTHETIC", "loopback", ["127.0.0.0/8"], [], [{
            "dns_domain": "synthetic.test", "netbios_name": "DECLARED", "forest": "synthetic.test",
            "scopes": ["127.0.0.0/8"], "evidence_state": "declared"}], ["snmp"])
        result = self.resolve([wrapped(raw_evidence(name="router.synthetic.test"))], network(name=None), manifest)
        asset = next(x for x in result["assets"] if "snmp.sys_name" in x["field_provenance"])
        self.assertIsNone(asset["identity"]["realm_evidence_state"])
        self.assertIsNone(asset["identity"]["realm_name"])
        # Even a successful short-name/IP correlation cannot promote the remote suffix.
        correlated = self.resolve([wrapped(raw_evidence(name="router.synthetic.test"))], network(name="router"), manifest)
        self.assertEqual(len(correlated["assets"]), 1)
        self.assertIsNone(correlated["assets"][0]["identity"]["realm_evidence_state"])

    def test_uptime_variation_is_provenance_and_location_variation_is_conflict(self):
        other = raw_evidence(); other["collection"]["fields"][2]["value"] += 99
        other["collection"]["fields"][4]["value"] = "another rack"
        result = self.resolve([raw_evidence(), other]); asset = result["assets"][0]
        self.assertEqual(len(asset["field_provenance"]["snmp.sys_uptime_ticks"]), 2)
        self.assertEqual([x["field"] for x in asset["conflicts"]], ["snmp.sys_location"])

    def test_bundle_retains_exact_raw_bytes_and_contract_metadata(self):
        result = self.resolve([raw_evidence(), wrapped(raw_evidence("auth_only"))])
        path = self.package(result)
        validation = bundle.validate_bundle(path); self.assertTrue(validation["valid"])
        with zipfile.ZipFile(path) as archive:
            for target in self.targets:
                self.assertEqual(archive.read("evidence/credentialed/" + target.name), target.read_bytes())
        receipt = importer.import_bundle(path, self.root / "store", process=True)
        self.assertTrue(receipt["semantic_match"])

    def test_bundle_creation_rejects_recognized_malformed_snmp(self):
        doc = wrapped(); doc["enrichment"]["fields"][0]["oid"] = "1.3.6.1.2.1.1.1.0"
        self.seed = write_json(self.root / "network.json", network()); self.targets = [write_json(self.root / "target.json", doc)]
        with self.assertRaises(ValueError):
            bundle.create_bundle(self.root / "bad.p01bundle", "SYNTHETIC", "R1", "N1", self.seed, self.targets)

    def test_rehashed_archive_still_rejects_malformed_snmp_contract(self):
        path = self.package(self.resolve([raw_evidence()]))
        with zipfile.ZipFile(path) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        target_name = "evidence/credentialed/target-0.json"
        doc = json.loads(files[target_name]); doc["summary"]["collected_fields"] = 1
        files[target_name] = bundle.canonical_json_bytes(doc)
        manifest = json.loads(files["bundle-manifest.json"])
        for artifact in manifest["artifacts"]:
            artifact.update(sha256=bundle.digest_bytes(files[artifact["path"]]), size_bytes=len(files[artifact["path"]]))
        files["bundle-manifest.json"] = bundle.canonical_json_bytes(manifest)
        inventory = json.loads(files["integrity/sha256-manifest.json"])
        for entry in inventory["entries"]:
            entry.update(sha256=bundle.digest_bytes(files[entry["path"]]), size_bytes=len(files[entry["path"]]))
        files["integrity/sha256-manifest.json"] = bundle.canonical_json_bytes(inventory)
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in files.items(): archive.writestr(name, data)
        with self.assertRaisesRegex(ValueError, "invalid_snmp_evidence_contract"): bundle.validate_bundle(path)

    def test_replay_rejects_edge_field_coverage_source_and_extension_tamper(self):
        resolved = self.resolve([raw_evidence()])
        for i, mutation in enumerate((
            lambda p: p["assets"][0]["field_provenance"]["snmp.sys_location"][0].update(value="tampered"),
            lambda p: p["assets"][0]["field_provenance"]["snmp.sys_name"][0].update(source_id="src-false"),
            lambda p: p["assets"][0]["field_provenance"].pop("snmp.sys_services"),
            lambda p: p["inputs"]["snmp_evidence"][0]["fields"][0].update(status="not_available"),
            lambda p: p["inputs"]["snmp_evidence"][0].update(inventory_eligible=False),
            lambda p: p["inputs"]["snmp_evidence"][0]["source"].update(sha256="0" * 64),
            lambda p: p["metadata"].pop("snmp_evidence_version"),
            lambda p: p["inputs"].pop("snmp_evidence"),
            lambda p: p["assets"][0]["correlations"][1].update(score=999))):
            doc = copy.deepcopy(resolved); mutation(doc)
            with self.subTest(mutation=i), self.assertRaisesRegex(ValueError, "semantic"):
                importer.import_bundle(self.package(doc, "tamper-" + str(i)), self.root / ("store-" + str(i)), process=True)

    def test_legacy_semantic_projection_preserves_previous_shape(self):
        doc = {"assets": [], "summary": {}, "inputs": {}, "unresolved_observations": [], "ambiguous_correlations": []}
        self.assertEqual(set(importer.semantic_projection(doc)),
                         {"summary", "assets", "unresolved_observations", "ambiguous_correlations"})

    def test_resolver_json_schema_accepts_full_and_diagnostic_evidence(self):
        if not HAS_SCHEMA:
            # Default offline suite needs no optional schema package. Mandatory SNMP CI does.
            result = self.resolve([raw_evidence(), raw_evidence("auth_only")])
            self.assertEqual(result["summary"]["snmp_evidence_seen"], 2); return
        from jsonschema import Draft202012Validator
        schema = json.loads((ROOT / "schemas/p01-asset-resolver-schema-v0.4c.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.resolve([raw_evidence(), raw_evidence("auth_only")]))


class ManagedGates(unittest.TestCase):
    def test_plan_binding_no_default_snmp_execution_and_private_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            workspace, request_path, _, _ = managed(Path(td))
            before = runtime._load_state(workspace)
            artifact = before["artifacts"]["credential_plan"]
            self.assertEqual(artifact["snmp_requests_sha256"], runtime.digest_file(request_path))
            assert_private(self, (workspace / artifact["path"]).parent)
            with mock.patch.object(runtime, "_load_component", side_effect=AssertionError("dispatch import")), \
                 self.assertRaisesRegex(runtime.RuntimeErrorSafe, "enable-snmp"):
                runtime.run_credentialed_execution_dry_run(workspace)
            preview = runtime.run_credentialed_execution_dry_run(workspace, enable_snmp=True)
            self.assertEqual(preview["actions_ready"], 1); self.assertFalse(preview["secret_resolution_performed"])
            assert_private(self, Path(preview["job_json"]).parent)
            with self.assertRaisesRegex(runtime.RuntimeErrorSafe, "enable-snmp"):
                runtime.run_credentialed_execution_auth_only(workspace, ack_authorized_access=True)

    def test_changed_request_manifest_or_profile_blocks_preview_before_executor(self):
        for source in ("requests", "manifest", "profiles"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as td:
                workspace, request_path, manifest_path, profile_path = managed(Path(td))
                path = {"requests": request_path, "manifest": manifest_path, "profiles": profile_path}[source]
                path.write_bytes(path.read_bytes() + b" ")
                with mock.patch.object(runtime, "_load_component", side_effect=AssertionError("executor import")), \
                     self.assertRaisesRegex(runtime.RuntimeErrorSafe, "source inputs changed"):
                    runtime.run_credentialed_execution_dry_run(workspace, enable_snmp=True)

    def test_preview_resume_performs_no_io_and_replan_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            workspace, request_path, _, _ = managed(Path(td))
            preview = runtime.run_credentialed_execution_dry_run(workspace, enable_snmp=True)
            request_path.unlink()
            with mock.patch.object(runtime, "_load_component", side_effect=AssertionError("import")):
                cached = runtime.run_credentialed_execution_dry_run(workspace)
            self.assertEqual(cached["status"], "already_complete")
            self.assertEqual(cached["job_sha256"], preview["job_sha256"])
            with self.assertRaises(runtime.RuntimeErrorSafe): runtime.run_credential_plan(workspace, force_replan=True)

    def test_blocked_snmp_preview_cannot_dispatch_auth(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Disabled profile remains a visible planned endpoint, with no eligible action.
            workspace, request_path, _, profile_path = managed(root)
            doc = profiles(); doc["profiles"][0]["enabled"] = False
            write_json(profile_path, doc)
            runtime.run_credential_plan(workspace, force_replan=True, snmp_requests=request_path)
            runtime.run_credentialed_execution_dry_run(workspace, enable_snmp=True)
            state = runtime._load_state(workspace)
            assert_private(self, (workspace / state["artifacts"]["credentialed_execution_preview"]["path"]).parent)
            with self.assertRaisesRegex(runtime.RuntimeErrorSafe, "blocked or missing"):
                runtime.run_credentialed_execution_auth_only(workspace, ack_authorized_access=True, enable_snmp=True)


@unittest.skipUnless(HAS_SNMP, "optional qualified SNMP runtime is not installed")
class RealManagedFlow(unittest.TestCase):
    def setUp(self):
        self.environment = mock.patch.dict(os.environ, {"CANCA_TEST_COMMUNITY": COMMUNITY,
                                                        "CANCA_TEST_AUTH": AUTH, "CANCA_TEST_PRIV": PRIV})
        self.environment.start(); self.addCleanup(self.environment.stop)

    def flow(self, version="snmpv2c", missing=None):
        with LoopbackAgent(missing=missing) as agent, tempfile.TemporaryDirectory() as td:
            workspace, request_path, _, _ = managed(Path(td), agent.port, version)
            preview = runtime.run_credentialed_execution_dry_run(workspace, enable_snmp=True)
            self.assertEqual(agent.requests, [])
            auth = runtime.run_credentialed_execution_auth_only(workspace, ack_authorized_access=True, enable_snmp=True)
            self.assertEqual(agent.requests, [reader.FIELDS[0][1]])
            with self.assertRaisesRegex(runtime.RuntimeErrorSafe, "enable-snmp"):
                runtime.run_credentialed_execution_full(workspace, ack_authorized_access=True)
            full = runtime.run_credentialed_execution_full(workspace, ack_authorized_access=True, enable_snmp=True)
            self.assertEqual(full["status"], "full_completed")
            self.assertEqual(agent.requests, [reader.FIELDS[0][1]] + [field[1] for field in reader.FIELDS])
            paths = [Path(stage["job_json"]) for stage in (preview, auth, full)]
            self.assertEqual(len({path.parent for path in paths}), 3)
            for path in paths: assert_private(self, path.parent)
            resolved = runtime.run_asset_resolver(workspace)
            exported = runtime.export_bundle(workspace)
            state = runtime._load_state(workspace)
            bundle_path = workspace / state["artifacts"]["evidence_bundle"]["path"]
            validation = bundle.validate_bundle(bundle_path)
            self.assertTrue(validation["valid"])
            with zipfile.ZipFile(bundle_path) as archive:
                manifest = json.loads(archive.read("bundle-manifest.json"))
            creds = [item for item in manifest["artifacts"] if item["role"] == "credentialed_evidence"]
            self.assertEqual(len(creds), 1); self.assertIn("FULL", creds[0]["path"])
            receipt = importer.import_bundle(bundle_path, Path(td) / "store", process=True, require_outer_sidecar=True)
            self.assertTrue(receipt["semantic_match"])
            doc = json.loads(Path(resolved["resolver_json"]).read_text())
            self.assertEqual(doc["summary"]["logical_assets_resolved"], 1)
            coverage = doc["inputs"]["snmp_evidence"][0]
            self.assertEqual(coverage["summary"]["collected_fields"], 7 if missing else 8)
            self.assertEqual(state["artifacts"]["credentialed_execution_full"]["snmp_partial_targets"], int(bool(missing)))
            request_path.unlink()
            with mock.patch.object(runtime, "_load_component", side_effect=AssertionError("resume import")):
                for stage in (runtime.run_credentialed_execution_dry_run, runtime.run_credentialed_execution_auth_only,
                              runtime.run_credentialed_execution_full):
                    kwargs = {} if stage == runtime.run_credentialed_execution_dry_run else {"ack_authorized_access": False}
                    self.assertEqual(stage(workspace, **kwargs)["status"], "already_complete")
            self.assertEqual(len(agent.requests), 9)
            for value in (COMMUNITY, AUTH, PRIV, "env://"):
                for path in [workspace / runtime.STATE_REL, Path(resolved["resolver_json"]), *paths]:
                    self.assertNotIn(value, path.read_text())

    def test_v2c_portable_full_bundle_and_offline_replay(self): self.flow()
    def test_v3_authpriv_portable_full_bundle_and_offline_replay(self): self.flow("snmpv3")
    def test_partial_full_coverage_is_exportable_without_inventing_fields(self): self.flow(missing=reader.FIELDS[4][1])

    def test_failed_auth_has_no_implicit_retry_and_explicit_retry_uses_fresh_directory(self):
        with LoopbackAgent(denied=True) as agent, tempfile.TemporaryDirectory() as td:
            workspace, _, _, _ = managed(Path(td), agent.port)
            runtime.run_credentialed_execution_dry_run(workspace, enable_snmp=True)
            with self.assertRaises(runtime.RuntimeErrorSafe):
                runtime.run_credentialed_execution_auth_only(workspace, ack_authorized_access=True, enable_snmp=True)
            state = runtime._load_state(workspace); path = workspace / state["artifacts"]["credentialed_execution_auth"]["path"]
            snapshot = path.read_bytes()
            for stage in (runtime.run_credentialed_execution_auth_only, runtime.run_credentialed_execution_full):
                with self.assertRaises(runtime.RuntimeErrorSafe): stage(workspace, ack_authorized_access=True, enable_snmp=True)
            self.assertEqual(len(agent.requests), 1)
            agent.denied = False
            retried = runtime.run_credentialed_execution_auth_only(workspace, ack_authorized_access=True,
                                                                   enable_snmp=True, force_auth_retry=True)
            self.assertEqual(retried["status"], "auth_validated")
            self.assertNotEqual(Path(retried["job_json"]).parent, path.parent)
            self.assertEqual(path.read_bytes(), snapshot); self.assertEqual(len(agent.requests), 2)

    def test_input_drift_after_auth_blocks_full_before_any_additional_get(self):
        with LoopbackAgent() as agent, tempfile.TemporaryDirectory() as td:
            workspace, request_path, manifest_path, profile_path = managed(Path(td), agent.port)
            runtime.run_credentialed_execution_dry_run(workspace, enable_snmp=True)
            runtime.run_credentialed_execution_auth_only(workspace, ack_authorized_access=True, enable_snmp=True)
            for path in (request_path, manifest_path, profile_path):
                original = path.read_bytes(); path.write_bytes(original + b" ")
                with self.assertRaises(runtime.RuntimeErrorSafe):
                    runtime.run_credentialed_execution_full(workspace, ack_authorized_access=True, enable_snmp=True)
                self.assertEqual(len(agent.requests), 1); path.write_bytes(original)

    def test_cli_flags_follow_the_managed_stages_with_real_udp(self):
        with LoopbackAgent() as agent, tempfile.TemporaryDirectory() as td:
            workspace, _, _, _ = managed(Path(td), agent.port)
            base = [sys.executable, str(ROOT / "runtime/P01_Discovery_Node.py"), "run", "--workspace", str(workspace)]
            result = subprocess.run(base, capture_output=True, text=True, timeout=25)
            self.assertNotEqual(result.returncode, 0); self.assertEqual(agent.requests, [])
            for flags in (["--enable-snmp"], ["--enable-snmp", "--execute", "--auth-only", "--ack-authorized-access"],
                          ["--enable-snmp", "--execute", "--full-enrichment", "--ack-authorized-access"], []):
                result = subprocess.run(base + flags, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(len(agent.requests), 9)


if __name__ == "__main__": unittest.main()
