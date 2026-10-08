"""Tests for bounded v0.6.33 latest observed summaries."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import P01_Workspace_Signal_Summary as summary
from test_workspace_observed_signals import state

class SummaryTests(unittest.TestCase):
    def test_distinct_latest_values_and_provenance(self):
        s=state()
        a=s['observations'][0]
        a['signals']=[{'kind':'hostname','value':'alpha'},{'kind':'hostname','value':'beta'}]
        s['observations'][1]['signals']=[{'kind':'hostname','value':'newer'}]
        result=summary.summarize(s)
        field=result['fields'][0]
        self.assertEqual(field['values'][0]['value'],'alpha')
        self.assertEqual(field['values'][1]['value'],'beta')
        self.assertEqual(field['status'],'conflicting')
        self.assertEqual(field['values'][0]['provenance'][0]['collection_id'],'col-1')
        self.assertNotIn('newer',str(result))
        self.assertNotIn('manual-value',str(result))
        self.assertNotIn('/private/secrets',str(result))

    def test_empty_and_single_observation(self):
        s=state();s['observations']=[]
        self.assertEqual(summary.summarize(s)['fields'],[])
        s=state();self.assertEqual(summary.summarize(s)['fields'][0]['status'],'observed')

    def test_rejects_cross_workspace_model_result(self):
        with patch.object(summary.observed.model,'object_state',return_value={**state(),'workspace_id':'ws-b'}):
            with self.assertRaises(Exception):
                summary.object_summary(None,'ws-a',object(),'host-1')

    def test_requires_bounded_kinds(self):
        s=state();s['observations'][0]['signals']=[{'kind':'k'+str(i),'value':'v'} for i in range(101)]
        with self.assertRaises(Exception):
            summary.summarize(s)

    def test_preserves_expected_revision(self):
        with patch.object(summary.observed.model,'object_state',return_value=state()) as mock:
            self.assertEqual(summary.object_summary(None,'ws-a',object(),'host-1',expected_revision=7)['revision'],7)
            self.assertEqual(mock.call_args.kwargs,{'expected_revision':7})

if __name__=='__main__':unittest.main()
