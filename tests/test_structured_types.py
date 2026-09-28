"""Strict structured candidates from synthetic data, never active credentials."""
import json
import subprocess
import sys

import pytest

from agentlog_unified import structured_types as st


def labels(result):
    return {(r['category'], r['subtype']) for r in result['matches']}


def reasons(result):
    return {r['reason'] for r in result['gaps']}


def assert_contract(result):
    assert set(result) == {'matches', 'documents', 'gaps', 'counts', 'status'}
    assert result['status'] in st.STATUSES
    assert set(result['counts']) == st.COUNT_FIELDS
    assert all(type(v) is int and v >= 0 for v in result['counts'].values())
    for row in result['matches']:
        assert set(row) == st.MATCH_FIELDS
        assert all(row[k] in values for k, values in st.MATCH_LABELS.items())
        assert type(row['document_index']) is int
        assert all(type(n) is int and n >= -1 for n in row['node_path'])
        assert (row['decoded_start'] is None) == (row['decoded_end'] is None)
        if row['decoded_start'] is not None:
            assert row['node_kind'] == 'string' and 0 <= row['decoded_start'] < row['decoded_end']
    for row in result['documents']:
        assert set(row) == st.DOCUMENT_FIELDS and row['status'] in st.DOCUMENT_STATUSES
        assert row['format'] in {'whole_json', 'fenced_json'}
        assert 0 <= row['source_start'] < row['source_end']
    for row in result['gaps']:
        assert set(row) == st.GAP_FIELDS and row['reason'] in st.GAP_REASONS
        assert row['document_index'] is None or type(row['document_index']) is int
        assert all(type(n) is int and n >= -1 for n in row['node_path'])


def test_escaped_keys_values_and_leaf_unicode_offsets_are_not_cell_offsets():
    source = '  {"e\\u006dail":"中文🙂 fixture\\u0040example.invalid","user_id":7}  '
    result = st.classify_structured(source)
    assert labels(result) == {('PII', 'email'), ('QID', 'user_identifier')}
    literal = next(r for r in result['matches'] if r['basis'] == 'literal_shape')
    assert literal['node_path'] == [0] and literal['decoded_start'] == 4
    assert literal['decoded_end'] == 4 + len('fixture@example.invalid')
    assert literal['candidate_status'] == 'placeholder_or_example'
    document = result['documents'][0]
    assert (document['source_start'], document['source_end']) == (2, len(source) - 2)
    assert source[literal['decoded_start']:literal['decoded_end']] != 'fixture@example.invalid'
    assert_contract(result)


def test_duplicate_keys_preserved_with_distinct_ordinal_paths():
    result = st.classify_structured('{"e\\u006dail":"one@example.invalid","email":"two@example.test"}')
    assert result['counts']['duplicate_keys'] == 1
    assert [r['node_path'] for r in result['matches']] == [[0], [1]]
    assert all(r['rule'] == 'email_shape' for r in result['matches'])
    assert_contract(result)


def test_all_nodes_visited_without_sensitive_key_prefilter_or_context_inheritance():
    source = {'email': {'id': 9, 'name': 'ordinary'}, 'repo': {'id': 8, 'name': 'project'},
              'user': {'id': 7}, 'user_id': 6, 'arbitrary': ['fixture@example.test']}
    result = st.classify_structured(json.dumps(source))
    assert result['counts']['nodes_visited'] == 12
    assert result['counts']['unmapped_keys'] >= 5
    assert result['counts']['unsupported_nodes'] == 1
    assert {tuple(r['node_path']) for r in result['matches'] if r['subtype'] == 'user_identifier'} == {(2, 0), (3,)}
    assert next(r for r in result['matches'] if r['subtype'] == 'email')['node_path'] == [4, 0]
    assert not any(r['category'] == 'PII' and r['node_path'][0] == 0 for r in result['matches'])
    assert_contract(result)


def test_nested_containers_only_get_carrier_hints_and_children_use_their_own_keys():
    result = st.classify_structured('{"request_body":{"phone":"123-456"},"user":{"email":"fixture@example.test"}}')
    carriers = [r for r in result['matches'] if r['node_kind'] == 'object']
    assert carriers and all(r['candidate_status'] == 'carrier_candidate' and r['decoded_start'] is None for r in carriers)
    assert next(r for r in result['matches'] if r['subtype'] == 'phone')['node_path'] == [0, 0]
    assert next(r for r in result['matches'] if r['subtype'] == 'email')['node_path'] == [1, 0]


def test_json_fences_have_original_envelopes_and_ignore_other_languages():
    text = ('中文 intro\n```python\n{"password":"do not classify this code"}\n```\n'
            '```json\n{"user_id":7}\n```\nprose\n~~~JSON\n{"email":"fixture@example.test"}\n~~~\n')
    result = st.classify_structured(text)
    assert len(result['documents']) == 2 and result['counts']['ignored_fences'] == 1
    assert labels(result) == {('QID', 'user_identifier'), ('PII', 'email')}
    for i, document in enumerate(result['documents']):
        assert document['document_index'] == i and document['format'] == 'fenced_json'
        assert text[document['source_start']:document['source_end']].startswith(('```json', '~~~JSON'))
    assert_contract(result)


def test_unclosed_fence_never_parses_its_prefix_and_budget_counts_all_fences():
    result = st.classify_structured('```json\n{"user_id":3}\n')
    assert not result['matches'] and reasons(result) == {'unclosed_json_fence'}
    text = ('```json\n{"user_id":3}\n```\n') * 4
    result = st.classify_structured(text, max_documents=1)
    assert len(result['documents']) == 1 and result['counts']['documents_detected'] == 4
    assert reasons(result) == {'document_budget'} and result['status'] == 'partial'


def test_invalid_whole_prefix_does_not_hide_a_valid_explicit_json_fence():
    text = '[Bug report]\n```json\n{"email":"fixture@example.test"}\n```'
    result = st.classify_structured(text)
    assert [d['format'] for d in result['documents']] == ['whole_json', 'fenced_json']
    assert [d['status'] for d in result['documents']] == ['invalid_json', 'parsed_with_semantic_gaps']
    assert labels(result) == {('PII', 'email')}
    assert result['matches'][0]['document_index'] == 1
    assert result['status'] == 'partial' and reasons(result) == {'invalid_json'}
    assert_contract(result)


def test_nested_encoded_json_paths_and_no_outer_literal_duplicate():
    inner = {'email': 'fixture@example.test'}
    result = st.classify_structured(json.dumps({'payload': json.dumps(inner)}))
    email = [r for r in result['matches'] if r['subtype'] == 'email']
    assert len(email) == 1 and email[0]['node_path'] == [0, -1, 0]
    assert result['counts']['encoded_json_parsed'] == 1
    carrier = next(r for r in result['matches'] if r['subtype'] == 'request_body')
    assert carrier['node_path'] == [0] and carrier['decoded_start'] is None
    twice = st.classify_structured(json.dumps(json.dumps(json.dumps(inner))))
    assert next(r for r in twice['matches'] if r['subtype'] == 'email')['node_path'] == [-1, -1, 0]
    assert twice['counts']['encoded_json_parsed'] == 2
    assert_contract(twice)


def test_decode_layer_limit_is_explicit_and_does_not_inherit_personal_types():
    text = json.dumps(json.dumps(json.dumps(json.dumps({'email': 'fixture@example.test'}))))
    result = st.classify_structured(text)
    assert 'decode_layer_budget' in reasons(result)
    assert result['counts']['encoded_json_parsed'] == 2
    assert result['status'] == 'partial'
    result = st.classify_structured(json.dumps({'email': json.dumps({'id': 4})}))
    assert not result['matches'] and result['counts']['unsupported_nodes'] == 1


@pytest.mark.parametrize('source', ['{"email":"x",}', '{"x":1}// comment', "{'email':'x'}", '[1,]', '"unclosed'])
def test_invalid_json_has_fixed_errors_and_no_partial_parse(source):
    result = st.classify_structured(source)
    assert result['status'] == 'invalid_json' and not result['matches']
    assert result['documents'][0]['status'] == 'invalid_json'
    assert reasons(result) == {'invalid_json'}
    assert_contract(result)


@pytest.mark.parametrize('value', ['NaN', 'Infinity', '-Infinity'])
def test_non_finite_constants_are_rejected_everywhere(value):
    for source in (value, '{"user_id":' + value + '}', '```json\n' + value + '\n```'):
        result = st.classify_structured(source)
        assert result['status'] == 'invalid_json' and not result['matches']
        assert reasons(result) == {'non_finite_json'}


def test_arbitrary_precision_number_marker_null_bool_and_empty_values():
    result = st.classify_structured('{"user_id":1e100000,"email":null,"password":false,"request_body":{},"response_body":[],"phone":""}')
    assert len(result['matches']) == 1
    number = result['matches'][0]
    assert number['subtype'] == 'user_identifier' and number['node_kind'] == 'number'
    assert number['basis'] == 'json_key_hint' and number['decoded_start'] is number['decoded_end'] is None
    assert result['counts']['null_nodes'] == result['counts']['boolean_nodes'] == 1
    assert result['counts']['empty_object_nodes'] == result['counts']['empty_array_nodes'] == result['counts']['empty_string_nodes'] == 1
    assert '1e100000' not in json.dumps(result)
    huge = st.classify_structured('{"user_id":' + '9' * 6000 + '}')
    assert len(huge['matches']) == 1 and huge['matches'][0]['node_kind'] == 'number'


def test_ordinary_whole_json_string_and_descriptive_mentions_have_no_key_evidence():
    result = st.classify_structured(json.dumps('Do not log password, user id or medical information.'))
    assert result['status'] == 'parsed_with_semantic_gaps' and not result['matches']
    assert result['counts']['unknown_nodes'] == 1
    assert st.classify_structured('Do not log passwords.')['status'] == 'not_applicable'
    assert st.classify_structured('https://example.invalid')['status'] == 'not_applicable'


def test_whitespace_strings_and_encoded_empty_containers_are_not_value_candidates():
    result = st.classify_structured(json.dumps({'email': ' \t\n', 'request_body': '{}', 'response_body': '[]'}))
    assert not result['matches']
    assert result['counts']['whitespace_string_nodes'] == 1
    assert result['counts']['empty_object_nodes'] == result['counts']['empty_array_nodes'] == 1
    assert result['counts']['encoded_json_parsed'] == 2
    assert_contract(result)


def test_match_budget_is_atomic_per_node_and_continues_other_nodes():
    result = st.classify_structured('{"request_body":"ordinary","user_id":7}', max_matches=1)
    assert labels(result) == {('QID', 'user_identifier')}
    assert result['matches'][0]['node_path'] == [1]
    assert result['counts']['match_budget_nodes'] == 1 and result['counts']['nodes_visited'] == 3
    assert result['gaps'] == [{'document_index': 0, 'node_path': [0], 'reason': 'match_budget'}]
    assert st.classify_structured('{"request_body":"ordinary"}', max_matches=1)['matches'] == []
    assert st.classify_structured('"fixture@example.test"', max_matches=0)['matches'] == []


def test_node_depth_source_key_and_literal_budgets_are_explicit():
    result = st.classify_structured('{"user_id":1,"email":"fixture@example.test"}', max_nodes=2)
    assert result['counts']['nodes_visited'] == 2 and reasons(result) == {'node_budget'}
    result = st.classify_structured('[[[1]]]', max_depth=1)
    assert result['status'] == 'partial' and reasons(result) == {'depth_budget'}
    result = st.classify_structured('{"user_id":7}', max_source_chars=5)
    assert result['documents'] == result['matches'] == [] and reasons(result) == {'source_size_budget'}
    result = st.classify_structured(json.dumps({'a' * 257: 'fixture@example.test'}))
    assert reasons(result) == {'key_size_budget'} and result['counts']['unmapped_keys'] == 1
    result = st.classify_structured(json.dumps('x' * 65537 + ' fixture@example.test'))
    assert not result['matches'] and reasons(result) == {'string_literal_size_budget'}


def test_budget_after_invalid_document_is_partial_not_invalid_only():
    result = st.classify_structured('```json\n{bad}\n```\n```json\n{"user_id":3}\n```\n', max_documents=1)
    assert result['status'] == 'partial' and reasons(result) == {'invalid_json', 'document_budget'}


def test_all_returned_fields_are_safe_no_values_dynamic_keys_or_hashes():
    value = 'ghp_' + '0123456789' * 3
    key = 'DYNAMIC_PRIVATE_KEY_SENTINEL_493'
    text = json.dumps({key: [{'password': value}, {'email': 'fixture-person@example.invalid'}]})
    result = st.classify_structured(text)
    assert_contract(result)
    serialized = json.dumps(result)
    for secret in (value, key, 'fixture-person@example.invalid'):
        assert secret not in serialized
    assert 'hash' not in serialized and 'source_text' not in serialized


@pytest.mark.parametrize('budgets', [{'max_nodes': -1}, {'max_matches': True}, {'max_depth': 257}, {'max_documents': 1.5}, {'max_decode_layers': 3}, {'max_source_chars': 0}])
def test_budget_validation_is_fixed_and_does_not_echo_input(budgets):
    with pytest.raises(ValueError) as exc:
        st.classify_structured('PRIVATE_SENTINEL_NOT_TO_ECHO', **budgets)
    assert 'PRIVATE_SENTINEL' not in str(exc.value)


def test_parser_limits_and_depth_preflight_are_fixed_gaps(monkeypatch):
    original = st.json.loads
    def recursion(*args, **kwargs): raise RecursionError('PRIVATE_SENTINEL')
    monkeypatch.setattr(st.json, 'loads', recursion)
    result = st.classify_structured('{"user_id":3}')
    assert reasons(result) == {'parser_recursion_limit'} and 'PRIVATE_SENTINEL' not in str(result)
    def value_limit(*args, **kwargs): raise ValueError('PRIVATE_SENTINEL')
    monkeypatch.setattr(st.json, 'loads', value_limit)
    result = st.classify_structured('{"user_id":3}')
    assert reasons(result) == {'parser_value_limit'}
    monkeypatch.setattr(st.json, 'loads', original)


def test_wide_and_deep_adversarial_synthetic_inputs_finish_boundedly():
    script = '''from agentlog_unified.structured_types import classify_structured
cases=['['+'1,'*100000+'1]', '['*10000+'1'+']'*10000, '"'+'a.'*300000+'"']
for source in cases:
    result=classify_structured(source,max_nodes=3,max_matches=1)
    assert result['status']=='partial' and result['gaps']
'''
    subprocess.run([sys.executable, '-c', script], capture_output=True, check=True, timeout=15)


def test_catalog_documents_limits_and_no_all_types_claim():
    catalog = st.detector_catalog()
    assert catalog['max_literal_chars'] == 65536
    assert 'not_original_cell' in catalog['leaf_offset_unit']
    assert 'No key prefilter' in catalog['selection']
    assert 'Atomic node' in catalog['match_cap_policy']
