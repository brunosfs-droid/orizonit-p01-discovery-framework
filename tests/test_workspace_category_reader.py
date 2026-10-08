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
                       dict(category='network',max_pages=True)):
                with self.assertRaises(model.pg.PersistenceError):
                    reader.inventory(None,'A',self.token,**kw)
            listing.assert_not_called()


if __name__=='__main__':unittest.main()
