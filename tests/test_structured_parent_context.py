"""Finite direct-parent JSON hints; no real identities or active credentials."""
import json
import pytest
from agentlog_unified import structured_types as st


def by_path(result,path):return [r for r in result['matches'] if r['node_path']==path]
def labels(rows):return {(r['category'],r['subtype']) for r in rows}


def test_immediate_parent_supplies_id_age_and_name_with_separate_basis():
 result=st.classify_structured('{"user":{"id":11,"age":21,"name":"Anonymous Person"},"user_id":9}')
 assert labels(by_path(result,[0,0]))=={('QID','user_identifier')}
 assert labels(by_path(result,[0,1]))=={('PII','age')}
 assert labels(by_path(result,[0,2]))=={('PII','person_name')}
 assert all(r['basis']=='json_parent_key_hint' for r in result['matches'] if len(r['node_path'])==2)
 assert by_path(result,[1])[0]['basis']=='json_key_hint'
 assert result['counts']['nodes_visited']==6
 assert result['status']=='parsed_with_semantic_gaps'


@pytest.mark.parametrize('parent,leaf,expected',[
 ('user','id',('QID','user_identifier')),('account','id',('QID','user_identifier')),
 ('order','id',('QID','transaction_identifier')),('session','id',('QID','session_identifier')),
 ('request','id',('QID','request_identifier')),('profile','age',('PII','age')),
 ('student','school',('PII','education')),('employee','jobTitle',('PII','employment')),
])
def test_controlled_combinations_only(parent,leaf,expected):
 result=st.classify_structured(json.dumps({parent:{leaf:7}}))
 rows=by_path(result,[0,0]);assert labels(rows)=={expected}
 assert rows[0]['basis']=='json_parent_key_hint' and rows[0]['node_kind']=='number'
 assert rows[0]['decoded_start'] is rows[0]['decoded_end'] is None


def test_request_body_is_carrier_without_request_type_on_its_id_or_headers():
 result=st.classify_structured('{"request":{"body":{"field":1},"headers":{"field":2},"id":3}}')
 assert ('BIZ','request_body') in labels(by_path(result,[0,0]))
 context=next(r for r in by_path(result,[0,0]) if r['subtype']=='request_body')
 assert context['basis']=='json_parent_key_hint' and context['candidate_status']=='carrier_candidate'
 assert context['value_status']=='opaque' and context['decoded_start'] is None
 assert labels(by_path(result,[0,1]))=={('BIZ','http_headers')}
 assert labels(by_path(result,[0,2]))=={('QID','request_identifier')}


@pytest.mark.parametrize('parent', ['APIKey','password','email','repository','catalog'])
def test_parent_sensitive_type_does_not_label_arbitrary_id_name_age_children(parent):
 result=st.classify_structured(json.dumps({parent:{'id':11,'name':'Anonymous Person','age':21}}))
 assert not [r for r in result['matches'] if len(r['node_path'])==2]
 assert result['counts']['nodes_visited']==5


def test_context_does_not_skip_an_intermediate_object():
 result=st.classify_structured('{"user":{"settings":{"id":1,"age":2}},"wrapper":{"user":{"id":3}}}')
 assert not by_path(result,[0,0,0]) and not by_path(result,[0,0,1])
 assert labels(by_path(result,[1,0,0]))=={('QID','user_identifier')}


def test_array_boundary_clears_outer_context_but_direct_inner_object_context_works():
 result=st.classify_structured('{"user":[{"id":1,"age":2},{"user":{"id":3}}]}')
 assert not by_path(result,[0,0,0]) and not by_path(result,[0,0,1])
 assert labels(by_path(result,[0,1,0,0]))=={('QID','user_identifier')}


def test_decoded_boundary_clears_outer_context_without_losing_ordinal_coordinates():
 result=st.classify_structured(json.dumps({'user':json.dumps({'id':1,'nested':{'user':{'id':2}}})}))
 assert not by_path(result,[0,-1,0])
 assert labels(by_path(result,[0,-1,1,0,0]))=={('QID','user_identifier')}
 assert all(r['basis']=='json_parent_key_hint' for r in by_path(result,[0,-1,1,0,0]))


def test_duplicate_escaped_keys_and_placeholders_keep_quality_and_paths():
 result=st.classify_structured('{"u\\u0073er":{"id":11,"id":"${subject.id}","name":"Synthetic Example","name":"Anonymous Person"}}')
 assert result['counts']['duplicate_keys']==2
 assert {tuple(r['node_path']) for r in result['matches'] if r['basis']=='json_parent_key_hint'}=={(0,0),(0,1),(0,2),(0,3)}
 reference=by_path(result,[0,1])[0]
 assert reference['candidate_status']=='identifier_reference' and reference['value_status']=='opaque'
 example=by_path(result,[0,2])[0]
 assert example['candidate_status']==example['value_status']=='placeholder_or_example'
 assert example['basis']=='json_parent_key_hint'
 public=json.dumps(result);assert 'Anonymous Person' not in public and 'subject.id' not in public
 assert all(set(r)==st.MATCH_FIELDS for r in result['matches'])


def test_null_boolean_empty_and_container_values_do_not_become_personal_values():
 result=st.classify_structured('{"user":{"id":null,"age":false,"name":" ","race":{},"school":[],"employment":{"id":1}}}')
 assert not [r for r in result['matches'] if len(r['node_path'])>1]
 assert result['counts']['null_nodes']==1 and result['counts']['boolean_nodes']==1
 assert result['counts']['whitespace_string_nodes']==1 and result['counts']['empty_object_nodes']==1
 assert result['counts']['empty_array_nodes']==1 and result['counts']['unknown_nodes']>=6


def test_match_cap_does_not_stop_tree_traversal_or_emit_partial_context_nodes():
 result=st.classify_structured('{"request":{"body":{"field":1},"id":2}}',max_matches=1)
 assert result['counts']['nodes_visited']==5
 assert result['status']=='partial' and 'match_budget' in {g['reason'] for g in result['gaps']}
 assert not by_path(result,[0,0]) and not by_path(result,[0,1])


def test_oversized_parent_key_retains_existing_gap_and_does_not_supply_context():
 result=st.classify_structured(json.dumps({'x'*257:{'id':1}}))
 assert 'key_size_budget' in {g['reason'] for g in result['gaps']}
 assert not by_path(result,[0,0])


def test_catalog_exposes_context_boundary_and_finite_basis():
 catalog=st.detector_catalog()
 assert catalog['structured_detector_version']=='1.1.0'
 assert 'json_parent_key_hint' in st.MATCH_LABELS['basis']
 assert any('array-element' in s and 'decode' in s for s in catalog['limitations'])


def test_adding_unrelated_parent_does_not_restore_receiver_pollution_in_dotted_leaf():
 result=st.classify_structured('{"wrapper":{"APIKey.id":1,"password.name":"Anonymous Person","user.metadata.id":3}}')
 assert not [r for r in result['matches'] if len(r['node_path'])==2]
