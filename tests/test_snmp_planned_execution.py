"""Explicit SNMP planning/execution contracts; synthetic IPv4 loopback only."""
from contextlib import ExitStack
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "orchestrator"))
import P01_Credentialed_Discovery_Planner as planner
import P01_Credentialed_Discovery_Executor as executor
import P01_SNMP_Planning as helper
from P01_Assessment_Context import build_manifest
from test_snmp_enricher import LoopbackAgent, HAS_SNMP, COMMUNITY, AUTH, PRIV, profiles, mod as adapter

HAS_SCHEMA = importlib.util.find_spec("jsonschema") is not None
if os.environ.get("CANCA_REQUIRE_SNMP_TESTS") == "1" and not HAS_SCHEMA:
    raise RuntimeError("SNMP CI requires the optional schema runtime")


def discovery(*ips):
    return {"metadata": {"run_label": "synthetic-snmp", "scanner_version": "0.4.1"},
            "assets": [{"ip": ip, "hostname": "synthetic-router", "vendor": "Synthetic",
                        "device_type_guess": "Router/Gateway", "os_guess": "Embedded",
                        "confidence": "High", "open_ports": []} for ip in ips or ("127.0.0.1",)]}


def requests(*endpoints):
    return {"schema_version": "0.4b.8", "endpoints": [
        {"target_ip": ip, "port": port, "profile_id": pid} for ip, port, pid in
        endpoints or (("127.0.0.1", 161, "network-read"),)]}


def plan(document=None, seeds=None, endpoints=None, **kwargs):
    return planner.build_plan(seeds or discovery(), document or profiles(),
                              snmp_requests=endpoints or requests(), **kwargs)


def protocol_plan(payload):
    return next(pp for pp in payload["assets"][0]["protocol_plans"] if pp["protocol"] == "snmp")


def assert_private(test, directory):
    if os.name != "nt":
        for path in [directory, *directory.rglob("*")]:
            test.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600, str(path))


class PlanningTests(unittest.TestCase):
    def test_no_request_preserves_observed_protocol_gate(self):
        result = planner.build_plan(discovery(), profiles())
        self.assertEqual(result["assets"][0]["protocol_plans"], [])
        self.assertEqual(result["assets"][0]["credentialed_action_status"], "not_planned")
        self.assertNotIn("snmp_extension_version", result["metadata"])

    def test_declared_endpoint_is_not_udp_observation_and_contains_no_refs(self):
        with mock.patch.object(adapter, "resolve_secret", side_effect=AssertionError("provider")), \
             mock.patch.object(executor, "dispatch", side_effect=AssertionError("network")):
            result = plan()
            ready = executor.run_job(result, profiles(), "a" * 64, Path("unused"), "dry", enable_snmp=True)
        asset, pp = result["assets"][0], protocol_plan(result)
        self.assertEqual(asset["detected_protocols"], [])
        self.assertEqual(result["summary"]["protocols"], [])
        self.assertEqual(result["summary"]["assets_with_protocols"], 0)
        self.assertEqual(pp["endpoint"]["source"], "operator_declared")
        self.assertEqual(pp["context"]["target_classes"], ["network_device", "router"])
        self.assertEqual(pp["authorization"]["authorized_scopes"], ["127.0.0.1/32"])
        self.assertEqual(ready["summary"]["dry_run_ready"], 1)
        self.assertFalse(ready["metadata"]["secret_resolution"])
        self.assertNotIn("env://", json.dumps(result)); self.assertNotIn("env://", json.dumps(ready))

    def test_explicit_profile_has_no_priority_selection_or_fallback(self):
        document = profiles(); other = copy.deepcopy(document["profiles"][0])
        other.update(id="higher-priority", priority=0)
        document["profiles"][0]["priority"] = 999
        document["profiles"].append(other)
        self.assertEqual(protocol_plan(plan(document))["eligible_profiles"][0]["profile"]["id"], "network-read")
        document["profiles"][0]["enabled"] = False
        self.assertEqual(protocol_plan(plan(document))["eligible_profile_count"], 0)

    def test_request_shape_literal_address_port_and_duplicates(self):
        for change in ({"target_ip": "localhost"}, {"target_ip": "::1"}, {"target_ip": "0.0.0.0"},
                       {"target_ip": "224.0.0.1"}, {"target_ip": "255.255.255.255"},
                       {"port": True}, {"port": 0}, {"port": 65536}, {"profile_id": " "}, {"extra": 1}):
            endpoint = requests(); endpoint["endpoints"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                plan(endpoints=endpoint)
        for document in ({"schema_version": "old", "endpoints": []},
                         {**requests(), "extra": 1}, {"schema_version": "0.4b.8", "endpoints": []},
                         requests(*[("127.0.0.1", 161, "network-read")] * 26),
                         requests(("127.0.0.1", 161, "network-read"), ("127.0.0.1", 162, "network-read"))):
            with self.subTest(document=document), self.assertRaises(ValueError):
                plan(endpoints=document)

    def test_unknown_or_ambiguous_seed_is_rejected(self):
        for seeds in (discovery("127.0.0.2"), discovery("127.0.0.1", "127.0.0.1")):
            with self.assertRaises(ValueError):
                plan(seeds=seeds)

    def test_request_reader_rejects_duplicate_keys_nonfinite_and_oversize(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "requests.json"
            for raw in (b'{"schema_version":"0.4b.8","schema_version":"0.4b.8"}',
                        b'{"port":NaN}', b'{"port":Infinity}', b" " * 65537):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    helper.load_requests(path)

    def test_manifest_protocol_scope_and_exclusion_are_separate_gates(self):
        manifest = build_manifest("SYNTHETIC", "loopback", ["127.0.0.0/8"], [], [], ["snmp"])
        pp = protocol_plan(plan(manifest=manifest))
        self.assertEqual(pp["authorization"]["source"], "assessment_manifest")
        for key, value in (("allowed_protocols", ["ssh"]), ("authorized_scopes", ["127.0.0.2/32"]),
                           ("allowed_protocols", ["snmp", 1]), ("authorized_scopes", [127001]),
                           ("exclude_scopes", ["127.0.0.1/32"]), ("exclude_scopes", ["0.0.0.0/0"]),
                           ("authorized_scopes", ["0.0.0.0/0"])):
            changed = copy.deepcopy(manifest); changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                plan(manifest=changed)
        outside = profiles(); outside["profiles"][0]["scopes"] = ["127.0.0.2/32"]
        self.assertEqual(protocol_plan(plan(outside, manifest=manifest))["eligible_profile_count"], 0)

    def test_unknown_and_taxonomy_do_not_become_eligible_from_hint(self):
        seeds = discovery(); seeds["assets"][0].update(device_type_guess="Unknown", os_guess="Unknown")
        document = profiles(); document["profiles"][0]["selectors"] = {"services": ["snmp"]}
        self.assertEqual(protocol_plan(plan(document, seeds))["eligible_profile_count"], 0)
        document["profiles"][0]["selectors"]["allow_unknown"] = True
        self.assertEqual(protocol_plan(plan(document, seeds))["eligible_profile_count"], 1)
        document["profiles"][0]["target_classes"] = ["windows"]
        self.assertEqual(protocol_plan(plan(document, seeds))["eligible_profile_count"], 0)

    def test_declared_realm_and_conflict_never_bypass_observed_gate(self):
        manifest = build_manifest("SYNTHETIC", "loopback", ["127.0.0.0/8"], [], [{
            "dns_domain": "synthetic.test", "netbios_name": "SYNTHETIC", "forest": "synthetic.test",
            "scopes": ["127.0.0.0/8"], "evidence_state": "declared"}], ["snmp"])
        document = profiles(); document["profiles"][0].update(
            realm_kind="ad_domain", realm_name="SYNTHETIC", realm_evidence_min="observed")
        seeds = discovery()
        self.assertEqual(protocol_plan(plan(document, seeds, manifest=manifest))["eligible_profile_count"], 0)
        self.assertEqual(protocol_plan(plan(document, seeds, manifest=manifest,
                                           realm_map={"127.0.0.1": "SYNTHETIC"}))["eligible_profile_count"], 0)
        seeds["assets"][0]["hostname"] += ".synthetic.test"
        self.assertEqual(protocol_plan(plan(document, seeds, manifest=manifest))["eligible_profile_count"], 1)
        result = plan(document, seeds, manifest=manifest, realm_map={"127.0.0.1": "OTHER"})
        self.assertEqual(protocol_plan(result)["skip_reason"], "snmp_context_conflict")
        self.assertEqual(result["assets"][0]["credentialed_action_status"], "not_planned")

    def test_high_privilege_and_v3_security_are_checked_while_planning(self):
        for change in ({"privilege_class": "domain_admin", "high_privilege_acknowledged": False},
                       {"snmp_security": {"level": "authNoPriv"}},
                       {"secret_refs": {"auth_key": "env://CANCA_TEST_AUTH"}}):
            document = profiles("snmpv3"); document["profiles"][0].update(change)
            self.assertEqual(protocol_plan(plan(document))["eligible_profile_count"], 0)

    def test_private_plan_hash_unicode_label_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td) / "plan"
            path, sidecar = planner.write_output(directory, "coleta-sintética", plan())
            self.assertEqual(executor.verify(path, sidecar), hashlib.sha256(path.read_bytes()).hexdigest())
            original = path.read_bytes()
            assert_private(self, directory)
            with self.assertRaises(FileExistsError):
                planner.write_output(directory, "coleta-sintética", plan())
            self.assertEqual(path.read_bytes(), original)


class ExecutionGateTests(unittest.TestCase):
    def test_default_opt_in_disabled_even_for_valid_new_plan(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(executor, "dispatch", side_effect=AssertionError("network")):
            out = Path(td) / "unused"
            result = executor.run_job(plan(), profiles(), "a" * 64, out, "default", execute=True)
            self.assertEqual(result["actions"][0]["skip_reason"], "snmp_execution_opt_in_required")
            self.assertEqual(result["summary"]["completed"], 0)
            self.assertFalse(out.exists())

    def test_old_snmp_plan_without_extension_is_blocked(self):
        payload = plan(); del protocol_plan(payload)["snmp_extension_version"]
        action = executor.build_actions(payload, profiles(), enable_snmp=True)[0]
        self.assertEqual(action["skip_reason"], "snmp_plan_or_profile_drift")

    def test_live_profile_configuration_and_reference_drift_block_before_dispatch(self):
        document = profiles("snmpv3"); payload = plan(document)
        for change in ({"secret_refs": {"auth_key": "env://CHANGED", "priv_key": "env://CANCA_TEST_PRIV"}},
                       {"username": "changed-reader"}, {"scopes": ["127.0.0.0/8"]}, {"enabled": False},
                       {"snmp_security": {"level": "authPriv", "auth_protocol": "sha1", "privacy_protocol": "aes128"}}):
            live = copy.deepcopy(document); live["profiles"][0].update(change)
            with self.subTest(change=change), tempfile.TemporaryDirectory() as td, \
                 mock.patch.object(executor, "dispatch", side_effect=AssertionError("network")):
                result = executor.run_job(payload, live, "a" * 64, Path(td) / "job", "drift", execute=True, enable_snmp=True)
                self.assertEqual(result["summary"]["actions_blocked_preflight"], 1)
                self.assertEqual(result["summary"]["completed"], 0)

    def test_invalid_live_document_and_duplicate_profile_ids_are_blocked(self):
        payload = plan()
        for live in ({**profiles(), "schema_version": "changed"},
                     {"schema_version": "0.4b", "profiles": profiles()["profiles"] * 2}):
            self.assertEqual(executor.build_actions(payload, live, enable_snmp=True)[0]["execution_eligibility"], "blocked")

    def test_endpoint_authorization_context_and_snapshot_drift_are_blocked(self):
        for mutate in (lambda a, pp: a.update(vendor="Different"), lambda a, pp: a.update(target_classes=["windows"]),
                       lambda a, pp: a.update(context_conflicts=["conflict"]),
                       lambda a, pp: pp["endpoint"].update(port=162),
                       lambda a, pp: pp["endpoint"].update(timeout_seconds=5),
                       lambda a, pp: pp["authorization"].update(allowed_protocols=["ssh"]),
                       lambda a, pp: pp["context"].update(services=["ssh"]),
                       lambda a, pp: pp["eligible_profiles"][0].update(selector_score=0)):
            payload = plan(); mutate(payload["assets"][0], protocol_plan(payload))
            self.assertEqual(executor.build_actions(payload, profiles(), enable_snmp=True)[0]["execution_eligibility"], "blocked")

    def test_duplicate_and_action_budget_rejected_before_output_or_dispatch(self):
        duplicate = plan(); duplicate["assets"].append(copy.deepcopy(duplicate["assets"][0]))
        document = profiles(); document["profiles"][0]["scopes"] = ["127.0.0.0/8"]
        two = plan(document, discovery("127.0.0.1", "127.0.0.2"),
                   requests(("127.0.0.1", 161, "network-read"), ("127.0.0.2", 161, "network-read")))
        for payload, maximum in ((duplicate, 25), (two, 1)):
            with tempfile.TemporaryDirectory() as td, mock.patch.object(executor, "dispatch", side_effect=AssertionError("network")):
                directory = Path(td) / "unused"
                with self.assertRaises(ValueError):
                    executor.run_job(payload, document, "a" * 64, directory, "budget", execute=True,
                                     max_actions=maximum, enable_snmp=True)
                self.assertFalse(directory.exists())

    def test_existing_output_rejected_before_dispatch(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(executor, "dispatch", side_effect=AssertionError("network")):
            with self.assertRaises(FileExistsError):
                executor.run_job(plan(), profiles(), "a" * 64, Path(td), "existing", execute=True, enable_snmp=True)

    def test_dispatch_rechecks_live_profile_before_loading_adapter(self):
        document = profiles(); action = executor.build_actions(plan(document), document, enable_snmp=True)[0]
        document["profiles"][0]["secret_refs"]["community"] = "env://CHANGED"
        with mock.patch.object(executor, "mod", side_effect=AssertionError("adapter")), self.assertRaises(ValueError):
            executor.dispatch(action, document["profiles"][0], False, None, "strict")

    def test_dispatch_exception_is_fixed_and_private_output_is_exclusive(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(executor, "dispatch", side_effect=RuntimeError(COMMUNITY)):
            directory = Path(td) / "job"
            result = executor.run_job(plan(), profiles(), "a" * 64, directory, "error", execute=True, enable_snmp=True)
            target = Path(result["actions"][0]["target_result_file"])
            evidence = json.loads(target.read_text())
            self.assertEqual(evidence["authentication"]["result"], "executor_dispatch_exception")
            self.assertNotIn(COMMUNITY, target.read_text())
            self.assertNotIn("error", evidence["authentication"])
            assert_private(self, directory)
            with self.assertRaises(FileExistsError):
                executor.write(target, evidence)

    def test_execute_cli_acknowledgement_and_sha_guard_precede_output(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); profile = base / "profiles.json"; profile.write_text(json.dumps(profiles()))
            path, sidecar = planner.write_output(base / "plan", "guard", plan())
            args = [sys.executable, str(ROOT / "orchestrator/P01_Credentialed_Discovery_Executor.py"),
                    "--plan", str(path), "--profiles", str(profile), "--enable-snmp", "--execute", "--output-dir", str(base / "job")]
            for additional in ([], ["--ack-authorized-access"], ["--ack-authorized-access", "--plan-sha256", str(sidecar)]):
                if additional and "--plan-sha256" in additional:
                    path.write_text(path.read_text() + " ")
                result = subprocess.run(args + additional, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((base / "job").exists())

    def test_mixed_snmp_job_keeps_all_target_files_private(self):
        document = profiles(); ssh = copy.deepcopy(document["profiles"][0])
        ssh.update(id="ssh-read", protocol="ssh", auth_type="password", secret_refs={"password": "env://CANCA_TEST_SSH"})
        ssh["selectors"]["services"] = ["ssh"]
        document["profiles"].append(ssh)
        seeds = discovery(); seeds["assets"][0]["open_ports"] = [{"port": 22, "service": "ssh"}]
        with tempfile.TemporaryDirectory() as td, mock.patch.object(executor, "dispatch", return_value=(
                {"success": True}, {"collection_status": "collected"})):
            directory = Path(td) / "job"
            result = executor.run_job(plan(document, seeds), document, "a" * 64, directory,
                                      "mixed", execute=True, enable_snmp=True)
            self.assertEqual(result["summary"]["completed"], 2)
            assert_private(self, directory)

    @unittest.skipUnless(HAS_SCHEMA, "optional jsonschema runtime is not installed")
    def test_schemas_and_request_example(self):
        from jsonschema import Draft202012Validator, FormatChecker
        schema = json.loads((ROOT / "schemas/p01-snmp-requests-schema-v0.4b.8.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        validator.validate(requests())
        validator.validate(json.loads((ROOT / "orchestrator/snmp.requests.example.json").read_text()))
        job_schema = json.loads((ROOT / "schemas/p01-credentialed-job-schema-v0.4b.json").read_text())
        Draft202012Validator(job_schema).validate(executor.run_job(plan(), profiles(), "a" * 64, Path("unused"), "dry", enable_snmp=True))


@unittest.skipUnless(HAS_SNMP, "optional SNMP runtime is not installed")
class ProtocolExecutionTests(unittest.TestCase):
    def execute(self, document, seeds, endpoints, directory, auth_only=False):
        with mock.patch.dict(os.environ, {"CANCA_TEST_COMMUNITY": COMMUNITY, "CANCA_TEST_AUTH": AUTH,
                                         "CANCA_TEST_PRIV": PRIV, "CANCA_TEST_INDEPENDENT": COMMUNITY}):
            return executor.run_job(plan(document, seeds, endpoints), document, "a" * 64, directory,
                                    "synthetic", execute=True, auth_only=auth_only, enable_snmp=True)

    def test_real_planner_and_executor_clis_full_v2c_v3(self):
        for version in ("snmpv2c", "snmpv3"):
            with self.subTest(version=version), LoopbackAgent() as agent, tempfile.TemporaryDirectory() as td:
                base = Path(td)
                for name, data in (("profiles", profiles(version)), ("discovery", discovery()),
                                   ("requests", requests((agent.host, agent.port, "network-read")))):
                    (base / (name + ".json")).write_text(json.dumps(data))
                planned = subprocess.run([sys.executable, str(ROOT / "orchestrator/P01_Credentialed_Discovery_Planner.py"),
                    "--discovery", str(base / "discovery.json"), "--profiles", str(base / "profiles.json"),
                    "--snmp-requests", str(base / "requests.json"), "--output-dir", str(base / "plan")],
                    capture_output=True, text=True, timeout=20)
                self.assertEqual(planned.returncode, 0, planned.stderr)
                path = next((base / "plan").glob("*.json"))
                env = {**os.environ, "CANCA_TEST_COMMUNITY": COMMUNITY, "CANCA_TEST_AUTH": AUTH, "CANCA_TEST_PRIV": PRIV}
                executed = subprocess.run([sys.executable, str(ROOT / "orchestrator/P01_Credentialed_Discovery_Executor.py"),
                    "--plan", str(path), "--plan-sha256", str(path) + ".sha256", "--profiles", str(base / "profiles.json"),
                    "--output-dir", str(base / "job"), "--enable-snmp", "--execute", "--ack-authorized-access"],
                    env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(executed.returncode, 0, executed.stderr)
                job = json.loads(next((base / "job").glob("*.json")).read_text())
                self.assertEqual(job["summary"]["authentication_successes"], 1)
                target = Path(job["actions"][0]["target_result_file"])
                evidence = json.loads(target.read_text())
                self.assertEqual(evidence["metadata"]["plan_sha256"], executor.digest(path))
                self.assertEqual(executor.verify(target, str(target) + ".sha256"), job["actions"][0]["target_result_sha256"])
                self.assertEqual(evidence["enrichment"]["collection_status"], "collected")
                self.assertEqual(evidence["enrichment"]["summary"]["collected_fields"], 8)
                self.assertEqual(agent.requests, [field[1] for field in adapter.FIELDS])
                if version == "snmpv3":
                    self.assertTrue(all(message["model"] == 3 and message["level"] == 3 for message in agent.messages))
                for secret in (COMMUNITY, AUTH, PRIV):
                    self.assertNotIn(secret, target.read_text()); self.assertNotIn(secret, executed.stdout + executed.stderr)
                self.assertNotIn("env://", target.read_text())
                assert_private(self, base / "plan"); assert_private(self, base / "job")

    def test_auth_only_uses_one_probe_in_executor(self):
        with LoopbackAgent() as agent, tempfile.TemporaryDirectory() as td:
            result = self.execute(profiles("snmpv3"), discovery(), requests((agent.host, agent.port, "network-read")),
                                  Path(td) / "job", auth_only=True)
            target = json.loads(Path(result["actions"][0]["target_result_file"]).read_text())
            self.assertEqual(target["enrichment"]["collection_status"], "access_probe_only")
            self.assertEqual(agent.requests, [adapter.FIELDS[0][1]])

    def test_denied_read_stops_shared_alias_credential_but_independent_profile_runs(self):
        with ExitStack() as stack:
            first = stack.enter_context(LoopbackAgent(denied=True))
            second = stack.enter_context(LoopbackAgent(host="127.0.0.2"))
            third = stack.enter_context(LoopbackAgent(host="127.0.0.3"))
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory())) / "job"
            document = profiles(); document["profiles"][0]["scopes"] = ["127.0.0.0/8"]
            alias = copy.deepcopy(document["profiles"][0]); alias["id"] = "shared-alias"
            independent = copy.deepcopy(alias); independent.update(id="independent", secret_refs={"community": "env://CANCA_TEST_INDEPENDENT"})
            document["profiles"].extend([alias, independent])
            result = self.execute(document, discovery(first.host, second.host, third.host), requests(
                (first.host, first.port, "network-read"), (second.host, second.port, "shared-alias"),
                (third.host, third.port, "independent")), directory)
            self.assertEqual(result["actions"][1]["skip_reason"], "snmp_read_access_not_confirmed")
            self.assertEqual(result["summary"]["completed"], 2)
            self.assertEqual(result["summary"]["authentication_successes"], 1)
            self.assertEqual(result["summary"]["snmp_unconfirmed_credential_circuits"], 1)
            self.assertEqual(first.requests, [adapter.FIELDS[0][1]])
            self.assertEqual(second.requests, [])
            self.assertEqual(third.requests, [field[1] for field in adapter.FIELDS])
            self.assertTrue(all(circuit["authentication_failures"] == 0 and not circuit["circuit_open"]
                                for circuit in result["credential_circuits"].values()))

    def test_partial_full_does_not_suspend_shared_credentials(self):
        with ExitStack() as stack:
            first = stack.enter_context(LoopbackAgent(missing=adapter.FIELDS[4][1]))
            second = stack.enter_context(LoopbackAgent(host="127.0.0.2"))
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory())) / "job"
            document = profiles(); document["profiles"][0]["scopes"] = ["127.0.0.0/8"]
            result = self.execute(document, discovery(first.host, second.host), requests(
                (first.host, first.port, "network-read"), (second.host, second.port, "network-read")), directory)
            self.assertEqual(result["summary"]["authentication_successes"], 2)
            self.assertEqual(result["summary"]["snmp_unconfirmed_credential_circuits"], 0)
            self.assertEqual(result["actions"][0]["collection_status"], "collected_with_field_failures")
            self.assertEqual(len(first.requests), 8); self.assertEqual(len(second.requests), 8)

    def test_wrong_community_remains_unconfirmed_without_authentication_penalty(self):
        with ExitStack() as stack:
            first = stack.enter_context(LoopbackAgent(community="other-synthetic-community"))
            second = stack.enter_context(LoopbackAgent(host="127.0.0.2"))
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory())) / "job"
            document = profiles(); document["profiles"][0]["scopes"] = ["127.0.0.0/8"]
            result = self.execute(document, discovery(first.host, second.host), requests(
                (first.host, first.port, "network-read"), (second.host, second.port, "network-read")), directory)
            self.assertEqual(result["actions"][0]["failure_category"], "transport_or_silent_denial")
            self.assertEqual(result["actions"][1]["skip_reason"], "snmp_read_access_not_confirmed")
            self.assertFalse(result["actions"][0]["counts_against_credential_budget"])
            self.assertEqual(next(iter(result["credential_circuits"].values()))["authentication_failures"], 0)
            self.assertEqual(first.requests, []); self.assertEqual(second.requests, [])


if __name__ == "__main__":
    unittest.main()
