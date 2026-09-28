"""Synthetic contract tests only: no sealed cases, no accuracy evaluation."""
import copy,unittest
from agent_log_review_delivery import validate_annotation,prompt_kind

class ReviewContracts(unittest.TestCase):
    def setUp(self):
        self.e={'modification_id':'m','repository':'r/p','modification_sha':'a'*40,'file_path':'x.py','observed_change':{'before_lines':[1,1],'after_lines':[1,1]}}
        self.ev={'one':{'text':'Reduce repetitive logs.','equivalence_group':'g1'},'two':{'text':'Keep every repetitive log.','equivalence_group':'g2'}}
        self.l={('m','one'):[{'relation':'modification_context'}],('m','two'):[{'relation':'modification_context'}]}
        self.a={'status':'explicit','labels':['noise_control'],'target_anchor':{k:self.e[k] for k in ('repository','modification_sha','file_path')},
           'stated_purpose':'Reduce noise','direct_correspondence':'exact changed statement','citations':[{'evidence_id':'one','quote':'Reduce repetitive logs.','role':'purpose_support','claim_key':'noise','position':'supports'}]}
        self.a['target_anchor'].update(before_lines=[1,1],after_lines=[1,1])
    def check(self):return validate_annotation(self.a,self.e,self.ev,self.l)
    def test_valid_explicit(self):self.assertTrue(self.check())
    def test_wrong_commit(self):
        self.a['target_anchor']['modification_sha']='b'*40
        with self.assertRaisesRegex(ValueError,'wrong_target'):self.check()
    def test_wrong_lines(self):
        self.a['target_anchor']['after_lines']=[2,2]
        with self.assertRaisesRegex(ValueError,'wrong_target_lines'):self.check()
    def test_unassociated_quote(self):
        self.l={}
        with self.assertRaisesRegex(ValueError,'unassociated'):self.check()
    def test_fabricated_quote(self):
        self.a['citations'][0]['quote']='Make everything faster'
        with self.assertRaisesRegex(ValueError,'invalid_quote'):self.check()
    def test_introduction_background(self):
        self.l[('m','one')][0]['relation']='introduction_background'
        with self.assertRaisesRegex(ValueError,'background_only'):self.check()
    def test_referenced_prior_pr_not_direct_purpose(self):
        self.l[('m','one')][0]['relation']='referenced_dependency_background'
        with self.assertRaisesRegex(ValueError,'background_only'):self.check()
    def test_unknown_without_evidence_is_valid(self):
        self.a.update(status='unknown',labels=['unknown'],citations=[],unknown_reason='source_missing')
        self.assertTrue(self.check())
    def test_inference_not_automatically_explicit(self):
        self.a.update(status='inferred',stated_purpose=None,contextual_inference='Possibly reduce noise')
        self.assertTrue(self.check())
    def test_explicit_requires_correspondence(self):
        self.a['direct_correspondence']=None
        with self.assertRaisesRegex(ValueError,'explicit_missing'):self.check()
    def opposite(self):
        self.a['citations'].append({'evidence_id':'two','quote':'Keep every repetitive log.','role':'purpose_support','claim_key':'noise','position':'opposes'})
    def test_distinct_opposing_evidence(self):
        self.opposite();self.a['status']='conflicting';self.assertTrue(self.check())
    def test_conflict_cannot_be_overwritten_by_explicit(self):
        self.opposite()
        with self.assertRaisesRegex(ValueError,'unresolved_conflict'):self.check()
    def test_different_topics_not_conflicting(self):
        self.opposite();self.a['citations'][1]['claim_key']='different_target'
        self.assertTrue(self.check())
    def test_duplicate_evidence_not_independent_conflict(self):
        self.opposite();self.ev['two']['equivalence_group']='g1';self.a['status']='conflicting'
        with self.assertRaisesRegex(ValueError,'conflict_without'):self.check()
    def test_found_prompt_not_intent(self):
        self.assertEqual(prompt_kind('Base directory for this skill: /a'),'skill_injection')
        self.assertEqual(prompt_kind('This session is being continued from earlier'),'session_summary')
        self.assertEqual(prompt_kind('<task-notification>hello'),'tool_notification')
        self.assertEqual(prompt_kind('continue'),'short_turn_needs_context')

if __name__=='__main__':unittest.main()
