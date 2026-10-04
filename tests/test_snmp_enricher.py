"""Synthetic-only SNMP contracts and real loopback UDP/USM qualification."""
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("p01_snmp", ROOT / "credentialed_enrichment/P01_SNMP_Enricher.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)
HAS_SNMP = importlib.util.find_spec("pysnmp") is not None
if os.environ.get("CANCA_REQUIRE_SNMP_TESTS") == "1" and not HAS_SNMP:
    raise RuntimeError("SNMP CI requires the optional runtime")

COMMUNITY = "synthetic-community-C21"
AUTH = "synthetic-auth-key-A31"
PRIV = "synthetic-privacy-key-P41"
CONTEXT = {"device_type": "Router/Gateway", "services": ["snmp"], "confidence": "High"}


def profiles(version="snmpv2c"):
    profile = {"id": "network-read", "protocol": "snmp", "auth_type": version,
               "scopes": ["127.0.0.1/32"], "enabled": True,
               "selectors": {"services": ["snmp"], "device_types": ["Router/Gateway"]},
               "secret_refs": {"community": "env://CANCA_TEST_COMMUNITY"}}
    if version == "snmpv3":
        profile.update(username="synthetic-reader", snmp_security=dict(mod.SECURITY),
                       secret_refs={"auth_key": "env://CANCA_TEST_AUTH", "priv_key": "env://CANCA_TEST_PRIV"})
    return {"schema_version": "0.4b", "profiles": [profile]}


def provider(ref):
    return {"env://CANCA_TEST_COMMUNITY": COMMUNITY,
            "env://CANCA_TEST_AUTH": AUTH, "env://CANCA_TEST_PRIV": PRIV}[ref]


def run(document=None, **kwargs):
    result = mod.collect(document or profiles(), "127.0.0.1", "network-read", CONTEXT,
                         provider=provider, **kwargs)
    if os.environ.get("CANCA_REQUIRE_SNMP_TESTS") == "1":
        from jsonschema import Draft202012Validator, FormatChecker
        schema = json.loads((ROOT / "schemas/p01-snmp-enrichment-schema-v0.4b.7.json").read_text())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    return result


class InputTests(unittest.TestCase):
    def test_dry_run_no_provider_client_or_snmp_import(self):
        with mock.patch.object(mod, "resolve_secret", side_effect=AssertionError()), \
             mock.patch.object(mod, "SNMPClient", side_effect=AssertionError()):
            result = run(client_factory=lambda: self.fail("dry run opened a client"))
        self.assertEqual(result["metadata"]["execution_mode"], "dry_run")
        self.assertEqual(result["summary"]["get_operations_attempted"], 0)
        self.assertEqual(result["authentication"]["result"], "not_attempted")

    def test_scope_protocol_disable_missing_and_context_gates(self):
        changes = (("scopes", ["192.0.2.1/32"]), ("protocol", "ssh"), ("enabled", False))
        for key, value in changes:
            document = profiles(); document["profiles"][0][key] = value
            with self.subTest(key=key), self.assertRaises(mod.InputError):
                run(document)
        for context in (None, {}, {"device_type": "Windows Host", "services": ["snmp"]}):
            with self.subTest(context=context), self.assertRaises(mod.InputError):
                mod.collect(profiles(), "127.0.0.1", "network-read", context)
        with self.assertRaises(mod.InputError):
            mod.collect(profiles(), "127.0.0.1", "absent", CONTEXT)

    def test_ipv4_literal_unicast_and_limits(self):
        for target in ("localhost", "::1", "0.0.0.0", "224.0.0.1", "255.255.255.255"):
            with self.subTest(target=target), self.assertRaises(mod.InputError):
                mod.collect(profiles(), target, "network-read", CONTEXT)
        for argument, value in (("port", 0), ("port", 65536), ("port", True),
                                ("timeout", float("nan")), ("timeout", float("inf")),
                                ("timeout", 0), ("timeout", 6), ("deadline", 46)):
            with self.subTest(argument=argument, value=value), self.assertRaises(mod.InputError):
                run(**{argument: value})

    def test_acknowledgement_and_auth_only_require_execute(self):
        for arguments in ({"execute": True}, {"auth_only": True}):
            with self.assertRaises(mod.InputError):
                run(**arguments)

    def test_v3_rejects_missing_or_weaker_policy_before_provider(self):
        for change in ({"level": "authNoPriv"}, {"auth_protocol": "sha1"}, {"privacy_protocol": "des"}):
            document = profiles("snmpv3"); document["profiles"][0]["snmp_security"].update(change)
            with self.assertRaises(mod.InputError):
                run(document, execute=True, authorized=True)
        for key in ("username", "snmp_security"):
            document = profiles("snmpv3"); del document["profiles"][0][key]
            with self.assertRaises(mod.InputError):
                run(document)

    def test_no_v1_extra_refs_or_plaintext(self):
        for version in ("snmpv1", "password", None):
            with self.assertRaises(mod.InputError):
                run(profiles(version))
        for version in ("snmpv2c", "snmpv3"):
            document = profiles(version); document["profiles"][0]["secret_refs"]["other"] = "env://EXTRA"
            with self.assertRaises(mod.InputError):
                run(document)
        document = profiles(); document["profiles"][0]["community"] = COMMUNITY
        with self.assertRaises(mod.InputError):
            run(document)

    def test_provider_failure_is_fixed_without_exception_or_locator(self):
        def fail(ref):
            raise RuntimeError(AUTH + " / " + ref)
        result = mod.collect(profiles(), "127.0.0.1", "network-read", CONTEXT,
                             execute=True, authorized=True, provider=fail)
        self.assertEqual(result["authentication"]["result"], "secret_unavailable")
        self.assertNotIn(AUTH, json.dumps(result)); self.assertNotIn("env://", json.dumps(result))

    def test_unusable_secret_precedes_client(self):
        for secret in ("", "x" * 256, None):
            result = mod.collect(profiles(), "127.0.0.1", "network-read", CONTEXT,
                                 execute=True, authorized=True, provider=lambda ref: secret,
                                 client_factory=lambda: self.fail("invalid secret opened a client"))
            self.assertEqual(result["authentication"]["result"], "secret_unavailable")

    def test_output_exclusive_and_hash_and_private_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "result"; directory.mkdir(mode=0o700)
            digest = mod.write_result(directory, run())
            self.assertEqual(hashlib.sha256((directory / "snmp.json").read_bytes()).hexdigest(), digest)
            self.assertEqual((directory / "snmp.json.sha256").read_text(), digest + "  snmp.json\n")
            if os.name != "nt":
                self.assertEqual((directory / "snmp.json").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                mod.write_result(directory, run())

    def test_cli_dry_run_help_and_denial_do_not_echo_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "profiles.json").write_text(json.dumps(profiles()))
            (base / "context.json").write_text(json.dumps(CONTEXT))
            arguments = [sys.executable, str(SPEC.origin), "--profiles", str(base / "profiles.json"),
                         "--context", str(base / "context.json"), "--profile-id", "network-read",
                         "--target", "127.0.0.1", "--output-dir", str(base / "result")]
            result = subprocess.run(arguments, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((base / "result/snmp.json").read_text())["summary"]["get_operations_attempted"], 0)
            denied = subprocess.run(arguments + ["--execute"], capture_output=True, text=True, timeout=15)
            self.assertEqual(denied.returncode, 2)
            unknown = subprocess.run(arguments + ["--community", COMMUNITY], capture_output=True, text=True, timeout=15)
            self.assertEqual(unknown.returncode, 2); self.assertNotIn(COMMUNITY, unknown.stderr)
            help_result = subprocess.run([sys.executable, str(SPEC.origin), "--help"], capture_output=True, text=True, timeout=15)
            self.assertEqual(help_result.returncode, 0)


@unittest.skipUnless(HAS_SNMP, "optional SNMP runtime is not installed")
class ResponseTests(unittest.TestCase):
    def setUp(self):
        from pysnmp.proto import rfc1902, rfc1905, errind
        self.types, self.exceptions, self.indications = rfc1902, rfc1905, errind

    def response(self, field, value, oid=None):
        return None, 0, 0, [(self.types.ObjectName(oid or field[1]), value)]

    def test_exact_oid_and_single_binding(self):
        field = mod.FIELDS[0]; value = self.types.ObjectIdentifier("1.3.6.1.4.1.9999")
        response = self.response(field, value, "1.3.6.1.2.1.1.1.0")
        self.assertEqual(mod.decode_response(field, response, {})["status"], "invalid_response")
        self.assertEqual(mod.decode_response(field, (None, 0, 0, []), {})["status"], "invalid_response")

    def test_missing_oids_and_access_denied(self):
        field = mod.FIELDS[1]
        response = self.response(field, self.exceptions.noSuchInstance)
        self.assertEqual(mod.decode_response(field, response, {})["status"], "not_available")
        self.assertEqual(mod.decode_response(field, (None, 16, 1, []), {})["status"], "access_denied")

    def test_text_redaction_before_persistence(self):
        field = mod.FIELDS[3]
        value = self.types.OctetString("name " + COMMUNITY + " " + AUTH + " " + PRIV)
        result = mod.decode_response(field, self.response(field, value), {"a": AUTH, "b": COMMUNITY, "c": PRIV})
        self.assertEqual(result["value"], "name <redacted> <redacted> <redacted>")

    def test_invalid_type_utf8_oversize_and_numeric_bounds(self):
        samples = ((mod.FIELDS[1], self.types.OctetString(b"\xff")),
                   (mod.FIELDS[1], self.types.OctetString("x" * 1025)),
                   (mod.FIELDS[2], self.types.Integer32(123)),
                   (mod.FIELDS[5], self.types.Integer32(128)),
                   (mod.FIELDS[6], self.types.Integer32(-1)),
                   (mod.FIELDS[7], self.types.Integer32(3)))
        for field, value in samples:
            with self.subTest(field=field[0]):
                self.assertNotEqual(mod.decode_response(field, self.response(field, value), {})["status"], "collected")

    def test_non_text_secret_collision_omitted(self):
        field = mod.FIELDS[2]
        result = mod.decode_response(field, self.response(field, self.types.TimeTicks(12345678)), {"a": "12345678"})
        self.assertEqual(result["status"], "sensitive_value_omitted"); self.assertNotIn("value", result)

    def test_typed_security_failure_and_timeout(self):
        for indication, expected in ((self.indications.requestTimedOut, "timeout"),
                                     (self.indications.wrongDigest, "security_error"),
                                     (self.indications.unknownUserName, "security_error")):
            self.assertEqual(mod.decode_response(mod.FIELDS[0], (indication, 0, 0, []), {})["status"], expected)

    def test_global_deadline_and_close_without_retries(self):
        class SlowClient:
            closed = False
            gets = 0
            async def open(self, *args):
                pass
            async def get(self, field):
                self.gets += 1
                await asyncio.sleep(3)
            def close(self):
                self.closed = True
        client = SlowClient(); start = time.monotonic()
        result = run(execute=True, authorized=True, timeout=1, deadline=0.1, client_factory=lambda: client)
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(client.gets, 1); self.assertTrue(client.closed)
        self.assertEqual(result["authentication"]["failure_category"], "transport_or_silent_denial")
        self.assertFalse(result["authentication"]["counts_against_credential_budget"])

    def test_client_exception_never_copies_secret(self):
        class BrokenClient:
            async def open(self, *args):
                raise RuntimeError(COMMUNITY)
            def close(self):
                raise RuntimeError(COMMUNITY)
        result = run(execute=True, authorized=True, client_factory=BrokenClient)
        self.assertEqual(result["collection"]["status"], "not_collected")
        self.assertNotIn(COMMUNITY, json.dumps(result))


class LoopbackAgent:
    """Actual UDP/SNMP server with synthetic data, no device or host collection."""
    def __init__(self, missing=None, denied=False, secret_text=False, community=COMMUNITY,
                 auth_key=AUTH, priv_key=PRIV, username="synthetic-reader"):
        self.ready = threading.Event(); self.error = None; self.requests = []; self.messages = []
        self.missing, self.denied, self.secret_text = missing, denied, secret_text
        self.community, self.auth_key, self.priv_key, self.username = community, auth_key, priv_key, username

    def __enter__(self):
        self.thread = threading.Thread(target=self.serve, daemon=True); self.thread.start()
        if not self.ready.wait(10):
            raise RuntimeError("synthetic agent startup timed out")
        if self.error:
            raise self.error
        return self

    def __exit__(self, *args):
        self.loop.call_soon_threadsafe(self.stop.set_result, None)
        self.thread.join(10)
        if self.thread.is_alive():
            raise RuntimeError("synthetic agent did not close")

    def serve(self):
        async def serve_async():
            from pysnmp.entity import engine, config
            from pysnmp.entity.rfc3413 import cmdrsp, context
            from pysnmp.carrier.asyncio.dgram import udp
            from pysnmp.proto import rfc1902, rfc1905
            from pysnmp.smi import error
            from pysnmp.hlapi.v3arch import asyncio as snmp
            self.loop = asyncio.get_running_loop(); self.stop = self.loop.create_future()
            self.engine = engine.SnmpEngine()
            transport = udp.UdpTransport().open_server_mode(("127.0.0.1", 0))
            config.add_transport(self.engine, udp.DOMAIN_NAME, transport)
            config.add_v1_system(self.engine, "synthetic-v2", self.community.encode("utf-8"))
            config.add_v3_user(self.engine, self.username.encode("utf-8"), snmp.USM_AUTH_HMAC192_SHA256,
                               self.auth_key.encode("utf-8"), snmp.USM_PRIV_CFB128_AES, self.priv_key.encode("utf-8"))
            config.add_vacm_user(self.engine, 2, "synthetic-v2", "noAuthNoPriv", (1, 3, 6, 1, 2, 1))
            config.add_vacm_user(self.engine, 3, self.username.encode("utf-8"), "authPriv", (1, 3, 6, 1, 2, 1))
            owner = self
            def observe(snmp_engine, execution_point, variables, callback_context):
                owner.messages.append({"model": int(variables["securityModel"]),
                                       "level": int(variables["securityLevel"]),
                                       "wire": bytes(variables["wholeMsg"])})
            self.engine.observer.register_observer(observe, "rfc3412.receiveMessage:request")
            values = [rfc1902.ObjectIdentifier("1.3.6.1.4.1.9999.1"), rfc1902.OctetString("Synthetic Router"),
                      rfc1902.TimeTicks(123456), rfc1902.OctetString("synthetic-router"),
                      rfc1902.OctetString("synthetic rack"), rfc1902.Integer32(72),
                      rfc1902.Integer32(4), rfc1902.Integer32(1)]
            if self.secret_text:
                values[3] = rfc1902.OctetString(COMMUNITY + " " + AUTH + " " + PRIV)
            data = {field[1]: value for field, value in zip(mod.FIELDS, values)}
            class Instrumentation:
                def read_variables(self, *bindings, **options):
                    result = []
                    for position, (name, _) in enumerate(bindings):
                        owner.requests.append(str(name))
                        if owner.denied:
                            raise error.AuthorizationError(idx=position)
                        result.append((name, rfc1905.noSuchInstance if str(name) == owner.missing
                                       else data.get(str(name), rfc1905.noSuchObject)))
                    return result
            snmp_context = context.SnmpContext(self.engine)
            snmp_context.unregister_context_name(b"")
            snmp_context.register_context_name(b"", Instrumentation())
            self.responder = cmdrsp.GetCommandResponder(self.engine, snmp_context)
            await transport._lport
            self.port = transport.transport.get_extra_info("sockname")[1]
            self.ready.set()
            try:
                await self.stop
            finally:
                self.engine.close_dispatcher()
        try:
            asyncio.run(serve_async())
        except Exception as exc:
            self.error = exc; self.ready.set()


@unittest.skipUnless(HAS_SNMP, "optional SNMP runtime is not installed")
class ProtocolTests(unittest.TestCase):
    def test_unicode_credentials_use_utf8_octets(self):
        community, auth, priv, username = "comunidade-sintética-C51", "chave-sintética-A61", "privacidade-sintética-P71", "leitor-sintético"
        for version in ("snmpv2c", "snmpv3"):
            document = profiles(version)
            if version == "snmpv3":
                document["profiles"][0]["username"] = username
            def unicode_provider(ref):
                return {"env://CANCA_TEST_COMMUNITY": community, "env://CANCA_TEST_AUTH": auth,
                        "env://CANCA_TEST_PRIV": priv}[ref]
            with self.subTest(version=version), LoopbackAgent(community=community, auth_key=auth,
                                                            priv_key=priv, username=username) as agent:
                result = mod.collect(document, "127.0.0.1", "network-read", CONTEXT, execute=True,
                                     authorized=True, auth_only=True, port=agent.port, provider=unicode_provider)
                self.assertTrue(result["authentication"]["success"])
                self.assertEqual(agent.requests, [mod.FIELDS[0][1]])

    def test_real_v2c_and_v3_full_gets_and_crypto(self):
        for version in ("snmpv2c", "snmpv3"):
            with self.subTest(version=version), LoopbackAgent() as agent:
                result = run(profiles(version), execute=True, authorized=True, port=agent.port)
                self.assertTrue(result["authentication"]["success"], result)
                self.assertEqual(result["collection"]["status"], "collected")
                self.assertEqual(result["summary"], {"get_operations_attempted": 8, "collected_fields": 8})
                self.assertEqual(agent.requests, [field[1] for field in mod.FIELDS])
                self.assertEqual(len(agent.messages), 8)
                for message in agent.messages:
                    self.assertEqual((message["model"], message["level"]), (3, 3) if version == "snmpv3" else (2, 1))
                    if version == "snmpv3":
                        for secret in (COMMUNITY, AUTH, PRIV):
                            self.assertNotIn(secret.encode(), message["wire"])
                    else:
                        self.assertIn(COMMUNITY.encode(), message["wire"])
                values = {row["field"]: row["value"] for row in result["collection"]["fields"]}
                self.assertEqual(values["sys_name"], "synthetic-router")
                self.assertEqual(values["ipv4_forwarding"], 1)
                for secret in (COMMUNITY, AUTH, PRIV):
                    self.assertNotIn(secret, json.dumps(result))

    def test_real_v3_auth_only_single_probe(self):
        with LoopbackAgent() as agent:
            result = run(profiles("snmpv3"), execute=True, authorized=True, auth_only=True, port=agent.port)
            self.assertTrue(result["authentication"]["success"])
            self.assertEqual(result["collection"]["status"], "access_probe_only")
            self.assertEqual(agent.requests, [mod.FIELDS[0][1]])

    def test_partial_missing_field_preserves_other_values(self):
        with LoopbackAgent(missing=mod.FIELDS[4][1]) as agent:
            result = run(execute=True, authorized=True, port=agent.port)
            self.assertEqual(result["collection"]["status"], "collected_with_field_failures")
            self.assertEqual(result["summary"]["collected_fields"], 7)
            self.assertEqual(result["collection"]["fields"][4]["status"], "not_available")
            self.assertEqual(result["collection"]["fields"][3]["value"], "synthetic-router")

    def test_real_denied_view_stops_after_probe(self):
        with LoopbackAgent(denied=True) as agent:
            result = run(execute=True, authorized=True, port=agent.port)
            self.assertFalse(result["authentication"]["success"])
            self.assertEqual(result["authentication"]["failure_category"], "remote_access_denied")
            self.assertEqual(agent.requests, [mod.FIELDS[0][1]])

    def test_wrong_v2c_community_is_silent_denial_without_fallback(self):
        with LoopbackAgent() as agent:
            result = mod.collect(profiles(), "127.0.0.1", "network-read", CONTEXT,
                                 execute=True, authorized=True, port=agent.port, timeout=0.2, deadline=2,
                                 provider=lambda ref: "wrong-synthetic-community")
            self.assertFalse(result["authentication"]["success"])
            self.assertEqual(result["authentication"]["failure_category"], "transport_or_silent_denial")
            self.assertFalse(result["authentication"]["counts_against_credential_budget"])
            self.assertEqual(agent.requests, [])
            self.assertEqual(result["summary"]["get_operations_attempted"], 1)

    def test_wrong_v3_key_never_downgrades_to_v2c(self):
        def wrong(ref):
            return "wrong-synthetic-key" if ref.endswith("AUTH") else provider(ref)
        with LoopbackAgent() as agent:
            result = mod.collect(profiles("snmpv3"), "127.0.0.1", "network-read", CONTEXT,
                                 execute=True, authorized=True, port=agent.port, timeout=0.2, deadline=2,
                                 provider=wrong)
            self.assertFalse(result["authentication"]["success"])
            self.assertEqual(agent.requests, [])
            self.assertEqual(result["summary"]["get_operations_attempted"], 1)
            self.assertEqual(result["credential_policy"]["auth_type"], "snmpv3")

    def test_real_remote_text_redacted_in_written_evidence(self):
        with LoopbackAgent(secret_text=True) as agent, tempfile.TemporaryDirectory() as temporary:
            result = run(profiles("snmpv3"), execute=True, authorized=True, port=agent.port)
            mod.write_result(Path(temporary), result)
            raw = (Path(temporary) / "snmp.json").read_text()
            for secret in (COMMUNITY, AUTH, PRIV):
                # v3 keys were resolved; v2c community was not used in this run.
                if secret != COMMUNITY:
                    self.assertNotIn(secret, raw)
            self.assertIn("<redacted>", raw)


if __name__ == "__main__":
    unittest.main()
