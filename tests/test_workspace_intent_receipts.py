"""R02: volatile one-use scan-intent review receipts never authorize execution."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"server"))
import P01_Workspace_Intent_Receipts as receipts
import P01_Workspace_Live_Intent as live
import P01_Workspace_Service as service
import test_workspace_coordinator as fixture

pg = receipts.pg


class ReviewReceiptTests(unittest.TestCase):
    setUp=fixture.CoordinatorTests.setUp
    cleanup=fixture.CoordinatorTests.cleanup
    opened=fixture.CoordinatorTests.opened

    def adapter(self):
        return service.WorkspaceService(self.c,service.SourceRoots({}),
            approved_scan_scopes=live.ApprovedScopes({
                "A":{"lab":{"networks":["192.168.100.0/24"],
                            "modes":["auth_only","full_enrichment"]}},
                "B":{"lab":{"networks":["172.31.250.0/24"],
                            "modes":["auth_only"]}}}))

    def preview(self,adapter,token,mode="auth_only"):
        return adapter.live_scan_intent(
            "writer",token,"lab",mode,ack_authorized_access=True)["scope_digest_sha256"]

    def issue(self,adapter,token,digest,mode="auth_only"):
        return adapter.record_scan_review("writer",token,"lab",mode,digest,
                                           ack_authorized_access=True)

    def consume(self,adapter,token,digest,receipt,mode="auth_only"):
        return adapter.consume_scan_review("writer",token,"lab",mode,digest,receipt)

    def test_review_is_bounded_one_use_and_non_executable(self):
        token=self.opened();adapter=self.adapter();digest=self.preview(adapter,token)
        with patch.object(service.legacy_jobs,"checkpoint") as scanner:
            receipt=self.issue(adapter,token,digest)
            self.assertEqual(receipt["status"],"review_recorded_only")
            self.assertFalse(receipt["execution_authorized"])
            self.assertEqual(len(receipt["review_receipt"]),48)
            self.assertEqual(adapter.scan_reviews.outstanding(),1)
            result=self.consume(adapter,token,digest,receipt["review_receipt"])
            self.assertEqual(result["status"],"review_consumed_only")
            self.assertFalse(result["authentication_performed"])
            scanner.assert_not_called()
        self.assertEqual(adapter.scan_reviews.outstanding(),0)
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_generation_stale"):
            self.consume(adapter,token,digest,receipt["review_receipt"])
        self.assertFalse(self.c._jobs)

    def test_ack_and_digest_mismatch_are_denied_without_receipt(self):
        token=self.opened();adapter=self.adapter();digest=self.preview(adapter,token)
        with self.assertRaises(pg.PersistenceError):
            adapter.record_scan_review("writer",token,"lab","auth_only",digest)
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_generation_stale"):
            self.issue(adapter,token,"0"*64)
        for bad in (None,1,True,{},'abc','f'*63):
            with self.subTest(value=bad):
                with self.assertRaises(pg.PersistenceError):
                    adapter.record_scan_review("writer",token,"lab","auth_only",bad,
                                               ack_authorized_access=True)
        self.assertEqual(adapter.scan_reviews.outstanding(),0)

    def test_mismatched_mode_does_not_consume_review(self):
        token=self.opened();adapter=self.adapter();digest=self.preview(adapter,token)
        receipt=self.issue(adapter,token,digest)["review_receipt"]
        full=self.preview(adapter,token,"full_enrichment")
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_generation_stale"):
            self.consume(adapter,token,full,receipt,"full_enrichment")
        self.assertEqual(adapter.scan_reviews.outstanding(),1)
        self.consume(adapter,token,digest,receipt)
        self.assertEqual(adapter.scan_reviews.outstanding(),0)

    def test_expiry_prevents_replay_even_in_same_generation(self):
        token=self.opened();adapter=self.adapter();digest=self.preview(adapter,token)
        tick=[100.0]
        adapter.scan_reviews=receipts.ReviewReceipts(ttl_seconds=3,clock=lambda:tick[0])
        receipt=self.issue(adapter,token,digest)["review_receipt"]
        tick[0]=103.0
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_generation_stale"):
            self.consume(adapter,token,digest,receipt)
        self.assertEqual(adapter.scan_reviews.outstanding(),0)

    def test_generation_and_workspace_switch_never_replay(self):
        a=self.opened();adapter=self.adapter();digest=self.preview(adapter,a)
        receipt=self.issue(adapter,a,digest)["review_receipt"]
        self.c.close("writer","A",a.generation);b=self.opened("B")
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_generation_stale"):
            self.consume(adapter,a,digest,receipt)
        other=self.preview(adapter,b)
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_generation_stale"):
            self.consume(adapter,b,other,receipt)
        self.assertEqual(adapter.scan_reviews.outstanding(),1)
        self.assertFalse(self.c._jobs)

    def test_role_revocation_prevents_review_consumption(self):
        token=self.opened();adapter=self.adapter();digest=self.preview(adapter,token)
        receipt=self.issue(adapter,token,digest)["review_receipt"]
        self.grants["writer"].remove(("A","workspace:write"))
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_access_denied"):
            self.consume(adapter,token,digest,receipt)
        self.assertEqual(adapter.scan_reviews.outstanding(),1)

    def test_capacity_is_fail_closed_and_expired_records_release_capacity(self):
        token=self.opened();adapter=self.adapter();digest=self.preview(adapter,token)
        tick=[0.0]
        adapter.scan_reviews=receipts.ReviewReceipts(ttl_seconds=2,max_entries=1,clock=lambda:tick[0])
        self.issue(adapter,token,digest)
        with self.assertRaisesRegex(pg.PersistenceError,"workspace_jobs_full"):
            self.issue(adapter,token,digest)
        tick[0]=2.1
        other=self.issue(adapter,token,digest)
        self.assertEqual(adapter.scan_reviews.outstanding(),1)
        self.consume(adapter,token,digest,other["review_receipt"])

    def test_invalid_receipt_never_consumes_valid_one(self):
        token=self.opened();adapter=self.adapter();digest=self.preview(adapter,token)
        receipt=self.issue(adapter,token,digest)["review_receipt"]
        for bad in ("a"*48,"A"*48,"a"*47,"a"*49,"../",""):
            with self.subTest(value=bad):
                with self.assertRaises(pg.PersistenceError):
                    self.consume(adapter,token,digest,bad)
        self.consume(adapter,token,digest,receipt)
        self.assertFalse(self.c._jobs)


if __name__=="__main__":
    unittest.main()
