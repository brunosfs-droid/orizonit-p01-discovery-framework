"""Bounded per-category observed-signal coverage contracts."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import P01_Workspace_Category_Signal_Coverage as coverage

def row(i):
    return {'object_id': 'host-%03d' % i, 'kind': 'host', 'origin': 'declared'}

def page(count, complete=True, cursor=None):
    return {'workspace_id':'ws-a','revision':7,'category':'compute',
            'objects':[row(i) for i in range(count)],
            'complete':complete,'next_after':cursor,
            'scanned':100 if not complete else count,
            'filters':{'site_id':None,'environment_id':None,'kind':None,'origin':None}}

def summary(oid):
    return {'status':'observed_summary','workspace_id':'ws-a','object_id':oid,
            'revision':7,'fields':[{'status':'observed'},{'status':'conflicting'}]}

class CategorySignalCoverageTests(unittest.TestCase):
    def test_limit_resume_preserves_unprocessed_matches(self):
        with patch.object(coverage.categories,'inventory',return_value=page(3)) as index, \
             patch.object(coverage.summary,'object_summary',side_effect=lambda c,w,t,oid,**k:summary(oid)) as history:
            result=coverage.overview(None,'ws-a',object(),category='compute',limit=2)
            self.assertEqual(result['next_after'],'host-001')
            self.assertFalse(result['complete'])
            self.assertEqual(result['evaluated_objects'],2)
            self.assertEqual(result['objects'][0]['conflicting_kind_count'],1)
            self.assertEqual(history.call_count,2)
            self.assertTrue(all(x.kwargs['expected_revision']==7 for x in history.call_args_list))
            self.assertEqual(index.call_args.kwargs['max_pages'],1)

    def test_empty_page_continues_and_complete_page_stops(self):
        with patch.object(coverage.categories,'inventory',return_value=page(0,False,'host-099')), \
             patch.object(coverage.summary,'object_summary') as history:
            result=coverage.overview(None,'ws-a',object(),category='compute')
            self.assertEqual(result['next_after'],'host-099')
            history.assert_not_called()
        with patch.object(coverage.categories,'inventory',return_value=page(1)), \
             patch.object(coverage.summary,'object_summary',return_value=summary('host-000')):
            result=coverage.overview(None,'ws-a',object(),category='compute')
            self.assertTrue(result['complete'])
            self.assertIsNone(result['next_after'])

    def test_absence_of_record_is_not_discovery_absence(self):
        with patch.object(coverage.categories,'inventory',return_value=page(1)), \
             patch.object(coverage.summary,'object_summary',return_value={**summary('host-000'),'fields':[]}):
            result=coverage.overview(None,'ws-a',object(),category='compute')
            self.assertEqual(result['collection_coverage'],'not_assessed')
            self.assertFalse(result['absence_implies_missing'])
            self.assertEqual(result['objects'][0]['observation_status'],'not_recorded_in_object_history')

    def test_cross_workspace_fails_closed(self):
        with patch.object(coverage.categories,'inventory',return_value={**page(1),'workspace_id':'ws-b'}), \
             patch.object(coverage.summary,'object_summary') as history:
            with self.assertRaises(Exception):
                coverage.overview(None,'ws-a',object(),category='compute')
            history.assert_not_called()
        with patch.object(coverage.categories,'inventory',return_value=page(1)), \
             patch.object(coverage.summary,'object_summary',return_value={**summary('host-000'),'workspace_id':'ws-b'}):
            with self.assertRaises(Exception):
                coverage.overview(None,'ws-a',object(),category='compute')

    def test_invalid_limits_rejected_before_scanning(self):
        for value in (0,21,True,1.2):
            with self.subTest(limit=value),patch.object(coverage.categories,'inventory') as inventory:
                with self.assertRaises(Exception):
                    coverage.overview(None,'ws-a',object(),category='compute',limit=value)
                inventory.assert_not_called()

if __name__=='__main__':unittest.main()
