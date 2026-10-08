"""Unit tests for bounded, revision-pinned workspace category projections."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import P01_Workspace_Category_Reader as reader

model=reader.model


class CategoryReaderTests(unittest.TestCase):
    def setUp(self):
        self.token=model.runtime.Token('A',1,'a'*32)
        self.row=lambda oid,kind:dict(object_id=oid,kind=kind,label=oid,site_id=None,
            environment_id=None,origin='declared',created_revision=0)

    def test_category_filtered_and_scoped(self):
        page=dict(workspace_id='A',revision=3,objects=[self.row('a','host'),self.row('b','vlan')],
                  has_more=False,next_after='b')
        with patch.object(model,'list_objects',return_value=page) as listing:
            result=reader.inventory(None,'A',self.token,category='network')
        self.assertEqual([x['object_id'] for x in result['objects']],['b'])
        self.assertTrue(result['complete'])
        listing.assert_called_once_with(None,'A',self.token,after='',limit=100,expected_revision=None)

    def test_second_page_is_fenced_by_first_revision(self):
        first=dict(workspace_id='A',revision=4,objects=[self.row('a','host')],
                   has_more=True,next_after='a')
        second=dict(workspace_id='A',revision=4,objects=[self.row('b','host')],
                    has_more=False,next_after='b')
        with patch.object(model,'list_objects',side_effect=[first,second]) as listing:
            result=reader.inventory(None,'A',self.token,category='compute')
        self.assertEqual([x['object_id'] for x in result['objects']],['a','b'])
        self.assertEqual(listing.call_args.kwargs['expected_revision'],4)

    def test_page_limit_never_implies_full_inventory(self):
        first=dict(workspace_id='A',revision=0,objects=[self.row('a','host')],
                   has_more=True,next_after='a')
        with patch.object(model,'list_objects',return_value=first):
            result=reader.inventory(None,'A',self.token,category='compute',max_pages=1)
        self.assertFalse(result['complete'])
        self.assertEqual(result['next_after'],'a')

    def test_resume_cursor_requires_revision_and_preserves_order(self):
        page=dict(workspace_id='A',revision=7,objects=[self.row('m','vlan')],
                  has_more=False,next_after='m')
        with patch.object(model,'list_objects',return_value=page) as listing:
            result=reader.inventory(None,'A',self.token,category='network',
                                    after='k',expected_revision=7)
        self.assertEqual(result['objects'][0]['object_id'],'m')
        listing.assert_called_once_with(None,'A',self.token,after='k',limit=100,expected_revision=7)
        with patch.object(model,'list_objects') as listing:
            for cursor,revision in (('k',None),('../B',2)):
                with self.assertRaises(model.pg.PersistenceError):
                    reader.inventory(None,'A',self.token,category='network',
                                     after=cursor,expected_revision=revision)
            listing.assert_not_called()

    def test_site_and_environment_filters_keep_cursor_over_all_scanned_objects(self):
        rows=[self.row('a','host'),self.row('b','host'),self.row('c','vlan')]
        rows[0]['site_id']='S1';rows[0]['environment_id']='E1'
        rows[1]['site_id']='S2';rows[1]['environment_id']='E1'
        page=dict(workspace_id='A',revision=3,objects=rows,has_more=False,next_after='c')
        with patch.object(model,'list_objects',return_value=page):
            result=reader.inventory(None,'A',self.token,category='compute',site_id='S1',environment_id='E1')
        self.assertEqual([x['object_id'] for x in result['objects']],['a'])
        self.assertEqual(result['scanned'],3)
        self.assertEqual(result['matched'],1)
        self.assertEqual(result['filters'],dict(site_id='S1',environment_id='E1'))
        self.assertTrue(result['complete'])

    def test_filtered_page_without_matches_still_has_next_cursor(self):
        p=dict(workspace_id='A',revision=4,objects=[self.row('x','vlan')],has_more=True,next_after='x')
        with patch.object(model,'list_objects',return_value=p):
            result=reader.inventory(None,'A',self.token,category='compute',site_id='S1',max_pages=1)
        self.assertEqual(result['objects'],[])
        self.assertFalse(result['complete'])
        self.assertEqual(result['next_after'],'x')
        self.assertEqual(result['scanned'],1)

    def test_kind_and_origin_narrow_category_without_reassigning(self):
        rows=[self.row('a','host'),self.row('b','host'),self.row('c','vlan')]
        rows[1]['origin']='observed'
        page=dict(workspace_id='A',revision=3,objects=rows,has_more=False,next_after='c')
        with patch.object(model,'list_objects',return_value=page):
            result=reader.inventory(None,'A',self.token,category='compute',kind='host',origin='observed')
        self.assertEqual([x['object_id'] for x in result['objects']],['b'])
        self.assertEqual(result['scanned'],3)
        self.assertEqual(result['matched'],1)
        self.assertEqual(result['filters']['origin'],'observed')

    def test_invalid_row_metadata_is_rejected_not_silently_ignored(self):
        for key,value in (('kind','secret'),('origin','admin'),('created_revision',True),
                          ('site_id','../B'),('label','')):
            obj=self.row('a','host');obj[key]=value
            page=dict(workspace_id='A',revision=0,objects=[obj],has_more=False,next_after='a')
            with patch.object(model,'list_objects',return_value=page):
                with self.assertRaises(model.pg.PersistenceError):
                    reader.inventory(None,'A',self.token,category='compute')

    def test_rejects_cross_workspace_or_drift(self):
        for bad in (dict(workspace_id='B',revision=2,objects=[],has_more=False,next_after=''),
                    dict(workspace_id='A',revision=3,objects=[],has_more=False,next_after='')):
            with patch.object(model,'list_objects',return_value=bad):
                with self.assertRaises(model.pg.PersistenceError):
                    reader.inventory(None,'A',self.token,category='compute',expected_revision=2)

    def test_unordered_duplicate_and_invalid_page_are_rejected(self):
        for page in (
            dict(workspace_id='A',revision=0,objects=[self.row('b','host'),self.row('a','host')],has_more=False,next_after='a'),
            dict(workspace_id='A',revision=0,objects=[self.row('a','host')],has_more=True,next_after='z'),
            dict(workspace_id='A',revision=0,objects=[],has_more=True,next_after=''),
        ):
            with patch.object(model,'list_objects',return_value=page):
                with self.assertRaises(model.pg.PersistenceError):
                    reader.inventory(None,'A',self.token,category='compute')

    def test_rejects_invalid_category_and_budget_before_sql(self):
        with patch.object(model,'list_objects') as listing:
            for kw in (dict(category='identity'),dict(category='network',max_pages=0),
                       dict(category='network',max_pages=True),dict(category='network',site_id='../B'),
                       dict(category='network',environment_id='bad path'),
                       dict(category='compute',kind='vlan'),dict(category='compute',origin='manual')):
                with self.assertRaises(model.pg.PersistenceError):
                    reader.inventory(None,'A',self.token,**kw)
            listing.assert_not_called()


if __name__=='__main__':unittest.main()
