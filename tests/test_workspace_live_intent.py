"""R02: no-execution scanner intent scopes, isolation and generation fencing."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"server"))
import P01_Workspace_Live_Intent as intent
import P01_Workspace_Service as service
import test_workspace_coordinator as fixture

pg = intent.pg


class PolicyInputTests(unittest.TestCase):
    def test_only_exact_trusted_private_ipv4_scopes_accepted(self):
        for bad in ("8.8.8.0/24", "0.0.0.0/0", "10.0.0.0/8",
                    "192.168.0.1/24", "::1/128", "127.0.0.1/32",
                    "169.254.0.0/24", "192.168.0.0/23", "192.168.1.1",
                    "172.15.0.0/24", "172.32.0.0/24"):
            with self.subTest(cidr=bad):
                with self.assertRaises(pg.PersistenceError):
                    intent.ApprovedScopes({"A":{"s":{"networks":[bad],"modes":["auth_only"]}}})

    def test_ambiguous_scope_and_privileged_fields_rejected(self):
        bad_specs=(
            {"networks":["192.168.100.0/24"],"modes":["full_enrichment"]},
            {"networks":["192.168.100.0/24"],"modes":["auth_only","auth_only"]},
            {"networks":["192.168.100.0/24"],"modes":["auth_only"],"credentials":"secret"},
            {"networks":["192.168.100.0/24","192.168.100.128/25"],"modes":["auth_only"]},
            {"networks":["192.168.100.0/24","192.168.100.0/24"],"modes":["auth_only"]},
            {"networks":[],"modes":["auth_only"]},
            {"networks":["10.0.0.0/24","10.0.1.0/24"],"modes":["auth_only"]},
        )
        for spec in bad_specs:
            with self.subTest(spec=spec):
                with self.assertRaises(pg.PersistenceError):
                    intent.ApprovedScopes({"A":{"safe":spec}})
        with self.assertRaises(pg.PersistenceError):
            intent.ApprovedScopes({"A":{"../B":{"networks":["10.0.0.0/32"],"modes":["auth_only"]}}})

    def test_mapping_immutable_and_ip_counts_bounded(self):
        scopes=intent.ApprovedScopes({"A":{"lab":{"networks":["192.168.100.20/32","172.31.250.0/31"],
                                                "modes":["auth_only","full_enrichment"]}}})
        self.assertEqual(scopes._lookup("A","lab")["hosts"],3)
        with self.assertRaises(TypeError):
            scopes._scopes["B"]={}
        with self.assertRaises(TypeError):
            scopes._lookup("A","lab")["networks"]=()
        with self.assertRaises(pg.PersistenceError):
            scopes._lookup("B","lab")


class PreviewTests(unittest.TestCase):
    setUp=fixture.CoordinatorTests.setUp
    cleanup=fixture.CoordinatorTests.cleanup
    opened=fixture.CoordinatorTests.opened

    def adapter(self):
        return service.WorkspaceService(self.c,service.SourceRoots({}),
            approved_scan_scopes=intent.ApprovedScopes({
                "A":{"lab":{"networks":["192.168.100.0/24"],"modes":["auth_only","full_enrichment"]}},
                "B":{"lab":{"networks":["172.31.250.0/24"],"modes":["auth_only"]}}
            }))

    def test_explicit_preview_has_no_executable_outputs_or_network_effects(self):
        token=self.opened()
        adapter=self.adapter()
        with patch.object(service.legacy_jobs,"checkpoint") as executor:
            one=adapter.live_scan_intent("writer",token,"lab","auth_only",ack_authorized_access=True)
            two=adapter.live_scan_intent("writer",token,"lab","auth_only",ack_authorized_access=True)
            executor.assert_not_called()
        self.assertEqual(one,two)
        self.assertEqual(one["status"],"preview_only")
        self.assertFalse(one["execution_authorized"])
        self.assertFalse(one["network_activity_performed"])
        self.assertFalse(one["authentication_performed"])
        self.assertEqual(one["network_count"],1)
        self.assertEqual(one["maximum_target_hosts"],254)
        self.assertEqual(len(one["scope_digest_sha256"]),64)
        for secret in ("192.168.100","lease_id","password","credentials","command"):
            self.assertNotIn(secret,str(one))
        self.assertEqual(self.c.snapshot("writer")["jobs"],0)

    def test_denial_precedes_lookup_or_any_external_activity(self):
        token=self.opened()
        adapter=self.adapter()
        for call in (
            lambda: adapter.live_scan_intent("reader",token,"lab","auth_only",ack_authorized_access=True),
            lambda: adapter.live_scan_intent("writer",token,"lab","auth_only"),
            lambda: adapter.live_scan_intent("writer",token,"lab","execute",ack_authorized_access=True),
            lambda: adapter.live_scan_intent("writer",token,"../B","auth_only",ack_authorized_access=True),
        ):
            with self.assertRaises(pg.PersistenceError):
                call()
        self.assertFalse(self.c._jobs)

    def test_revocation_and_workspace_switch_invalidate_preview(self):
        a=self.opened()
        adapter=self.adapter()
        first=adapter.live_scan_intent("writer",a,"lab","auth_only",ack_authorized_access=True)
        self.c.close("writer","A",a.generation)
        b=self.opened("B")
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_generation_stale"):
            adapter.live_scan_intent("writer",a,"lab","auth_only",ack_authorized_access=True)
        other=adapter.live_scan_intent("writer",b,"lab","auth_only",ack_authorized_access=True)
        self.assertNotEqual(first["scope_digest_sha256"],other["scope_digest_sha256"])
        self.assertEqual(other["maximum_target_hosts"],254)
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_access_denied"):
            adapter.live_scan_intent("writer",b,"lab","full_enrichment",ack_authorized_access=True)

    def test_grant_revocation_blocks_existing_token(self):
        token=self.opened()
        adapter=self.adapter()
        adapter.live_scan_intent("writer",token,"lab","auth_only",ack_authorized_access=True)
        self.grants["writer"].remove(("A","workspace:write"))
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_access_denied"):
            adapter.live_scan_intent("writer",token,"lab","auth_only",ack_authorized_access=True)
        self.assertFalse(self.c._jobs)

    def test_unknown_scope_never_falls_back_to_another_workspace(self):
        token=self.opened()
        adapter=self.adapter()
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_access_denied"):
            adapter.live_scan_intent("writer",token,"other","auth_only",ack_authorized_access=True)
        self.assertFalse(self.c._jobs)


if __name__ == "__main__":
    unittest.main()
