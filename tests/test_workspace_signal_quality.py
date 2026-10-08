"""Signal quality diagnostics tests, synthetic contract."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import P01_Workspace_Signal_Quality as quality
from test_workspace_observed_signals import state

class QualityTests(unittest.TestCase):
    def test_single_signal_and_provenance(self):
        s=quality.summary.summarize(state())
        r=quality.diagnose(s)
        self.assertEqual(r['observed_kind_count'],1)
        self.assertEqual(r['conflicting_kind_count'],0)
        self.assertEqual(r['fields'][0]['observation_references'],1)
        self.assertFalse(r['absence_implies_missing'])
        self.assertNotIn('manual-value',str(r))
        self.assertNotIn('/private/secrets',str(r))

    def test_conflicts_not_silently_resolved(self):
        s=state()
        s['observations'][0]['signals']=[{'kind':'hostname','value':'a'},{'kind':'hostname','value':'b'}]
        r=quality.diagnose(quality.summary.summarize(s))
        self.assertEqual(r['conflicting_kind_count'],1)
        self.assertEqual(r['fields'][0]['distinct_observed_values'],2)

    def test_invalid_claim_and_provenance_fail_closed(self):
        s=quality.summary.summarize(state())
        for key,value in [('source_refs_disclosed',True),('time_basis','device_time'),('declared_values_included',True)]:
            with self.subTest(key=key),self.assertRaises(Exception):
                quality.diagnose({**s,key:value})
        damaged=quality.summary.summarize(state())
        damaged['fields'][0]['values'][0]['provenance']=[]
        with self.assertRaises(Exception):quality.diagnose(damaged)

    def test_workspace_fence_delegated_to_summary(self):
        with patch.object(quality.summary,'object_summary',return_value=quality.summary.summarize(state())) as read:
            r=quality.object_quality(None,'ws-a',object(),'host-1',expected_revision=7)
            self.assertEqual(r['revision'],7)
            self.assertEqual(read.call_args.kwargs,{'expected_revision':7})
if __name__=='__main__':unittest.main()
