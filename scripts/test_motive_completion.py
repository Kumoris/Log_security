"""Adversarial checks for review state, evidence links, precise target scope, and conflicts."""
import unittest,copy,tempfile,json
from pathlib import Path
import complete_agent_log_motive_reviews as m

class ReviewChecks(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.events,cls.contexts,cls.repairs=m.verified_events();cls.es={e['modification_id']:e for e in cls.events};cls.ev,cls.links=m.sources()
  cls.ev,cls.links=m.supplemental(cls.ev,cls.links,cls.events);cls.index=m.indexed_links(cls.links)
  cls.gs={g['group_number']:g for g in m.read(m.OUT/'commit_groups.jsonl')}
 def sample(self):
  e=self.es['f091301ec72b6ce6de7b3dab'];a=m.annotate(e,self.gs[165],self.contexts[e['modification_id']],self.ev,self.links);return e,a
 def test_pending_is_null(self):
  for e in m.read(m.OUT/'inventory.jsonl'):self.assertIsNone(e['motive_status'])
 def test_prior_110_retained(self):self.assertEqual(len(m.read(m.OUT/'batches/000_prior_audit/annotations.jsonl')),110)
 def test_quote_offset_rejects(self):
  e,a=self.sample();a['citations'][0]['quote_start']+=1
  with self.assertRaisesRegex(ValueError,'offset'):m.validate_annotation(a,e,self.ev,self.index)
 def test_unlinked_source_rejects(self):
  e,a=self.sample();idx=copy.copy(self.index);idx.pop((e['modification_id'],a['citations'][0]['evidence_id']))
  with self.assertRaisesRegex(ValueError,'unassociated'):m.validate_annotation(a,e,self.ev,idx)
 def test_wrong_sha_rejects(self):
  e,a=self.sample();a['target_anchor']['modification_sha']='wrong'
  with self.assertRaisesRegex(ValueError,'wrong_target'):m.validate_annotation(a,e,self.ev,self.index)
 def test_background_cannot_support(self):
  e,a=self.sample();idx=copy.copy(self.index);idx[e['modification_id'],a['citations'][0]['evidence_id']]=[{'relation':'introduction_background'}]
  with self.assertRaisesRegex(ValueError,'background'):m.validate_annotation(a,e,self.ev,idx)
 def test_unknown_needs_reason(self):
  e,a=self.sample();a.update(status='unknown',unknown_reason=None)
  with self.assertRaisesRegex(ValueError,'unknown'):m.validate_annotation(a,e,self.ev,self.index)
 def test_opposing_distinct_sources_require_conflict(self):
  e,a=self.sample();ev=copy.deepcopy(self.ev);idx=copy.copy(self.index);c=copy.deepcopy(a['citations'][0]);eid=c['evidence_id']
  ev['opposing-fixture']=dict(ev[eid],evidence_id='opposing-fixture',equivalence_group='different-source-fixture')
  idx[e['modification_id'],'opposing-fixture']=[{'relation':'modification_context'}];c.update(evidence_id='opposing-fixture',position='opposes');a['citations'].append(c)
  with self.assertRaisesRegex(ValueError,'unresolved_conflict'):m.validate_annotation(a,e,ev,idx)
  a['status']='conflicting';self.assertTrue(m.validate_annotation(a,e,ev,idx))
 def test_conflict_not_invented(self):
  e,a=self.sample();a['status']='conflicting'
  with self.assertRaisesRegex(ValueError,'without_distinct'):m.validate_annotation(a,e,self.ev,self.index)
 def test_source_duplicate_not_independent_vote(self):
  e,a=self.sample();ev=copy.deepcopy(self.ev);idx=copy.copy(self.index);c=copy.deepcopy(a['citations'][0]);v=ev[c['evidence_id']]
  ev['duplicate-fixture']=dict(v,evidence_id='duplicate-fixture');idx[e['modification_id'],'duplicate-fixture']=[{'relation':'modification_context'}]
  c.update(evidence_id='duplicate-fixture',position='opposes');a['citations'].append(c)
  self.assertTrue(m.validate_annotation(a,e,ev,idx))
 def test_preserved_statement_can_have_explicit_guard_motive(self):
  e=self.es['208039e380111a404bad37ea'];a=m.annotate(e,self.gs[188],self.contexts[e['modification_id']],self.ev,self.links)
  self.assertEqual(e['observed_change']['before_statement'],e['observed_change']['after_statement']);self.assertEqual(a['status'],'explicit')
 def test_same_keyword_wrong_file_not_explicit(self):
  g=self.gs[3]
  for mid in g['event_ids']:
   a=m.annotate(self.es[mid],g,self.contexts[mid],self.ev,self.links);self.assertEqual(a['status'],'unknown')
 def test_existing_logging_not_stderr_conversion(self):
  for mid in self.gs[85]['event_ids']:
   if self.es[mid]['review_state']!='pending':continue
   a=m.annotate(self.es[mid],self.gs[85],self.contexts[mid],self.ev,self.links);self.assertEqual(a['status'],'unknown')
 def test_retained_context_not_deleted(self):
  e=self.es['a87b7f6652a254325c3d7837'];a=m.annotate(e,self.gs[316],self.contexts[e['modification_id']],self.ev,self.links)
  self.assertEqual(a['status'],'unknown');self.assertIn('context_retained',a['unknown_reason'])
 def test_missing_hunk_retained_unknown(self):
  e=next(e for e in self.events if e['current_observation']['classification']=='no_target_span_in_attached_diff');g=next(g for g in self.gs.values() if e['modification_id'] in g['event_ids'])
  a=m.annotate(e,g,self.contexts[e['modification_id']],self.ev,self.links);self.assertEqual(a['status'],'unknown')
 def test_unrelated_hunk_cannot_supply_context_change(self):
  e=copy.deepcopy(self.es['0fb02baae81f5a3eaab908ec']);r=next(r for r in m.RULES if r[6]=='context_arg');e['current_observation']['removed_target_lines']=[{'text':'other_call()'}]
  self.assertFalse(m.scope_check(r,e,self.contexts[e['modification_id']]))
 def test_original_line_fields_preserved_after_repair(self):
  self.assertEqual(len(self.repairs),9)
  e=self.es['d70d714ed89cca16d41bd28b'];self.assertEqual(e['observed_change']['before_lines'],[368,368]);self.assertEqual(e['span_corrections'][0]['verified_span'],[367,367])
 def test_new_issue_uses_explicit_prompt_reference(self):
  new=[l for ll in self.links.values() for l in ll if l['relation']=='modification_prompt_referenced_issue'];self.assertEqual(len(new),13)
  for l in new:
   b=l['association_basis'];self.assertEqual(b['reference_source'],'0dd6c6febbccffa7a9c107b2');self.assertIn('Issue #3',b['reference_quote'])
 def test_source_unique_ids(self):self.assertEqual(len(self.ev),3630)
 def test_no_double_review_in_resume_inventory(self):
  a=m.load_batches();self.assertEqual(len(a),len({x['modification_id'] for x in a}))
 def test_scope_quotes_exact(self):
  for r in m.RULES:self.assertIn(r[2],self.ev[r[1]]['text'])

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(ReviewChecks);result=unittest.TextTestRunner(verbosity=1).run(suite)
 m.write(m.OUT/'verification/regression_tests.json',{'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'status':'PASS' if result.wasSuccessful() else 'FAIL','at':m.now(),
  'scope':'synthetic/adversarial data-contract and reviewed real-case checks; not independent semantic accuracy evaluation'})
 raise SystemExit(not result.wasSuccessful())
