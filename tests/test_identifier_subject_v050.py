"""Synthetic static source only; no target application is executed."""
import pytest

from agentlog_unified.content_types import classify_text
from agentlog_unified.detector import _types, detect_snapshot
from agentlog_unified.taxonomy import _matches, field_subject, normalize_identifier


def tags(source, **kwargs):
    return {(r[0], r[1]) for r in _matches(source, **kwargs)}


def log(expression):
    source = 'import logging\ndef run(x, user, password, APIKey):\n    logging.info("value", ' + expression + ')\n'
    return detect_snapshot({'app.py': source})['entities'][0]


@pytest.mark.parametrize('name, normalized, label', [
    ('APIKey', 'api_key', ('AUTH', 'api_key')),
    ('IPAddress', 'ip_address', ('QID', 'network_identifier')),
    ('HTTPAuthorization', 'http_authorization', ('AUTH', 'authorization_header')),
    ('HTTPHeaders', 'http_headers', ('BIZ', 'http_headers')),
])
def test_acronym_boundaries_share_finite_field_classification(name, normalized, label):
    assert normalize_identifier(name) == normalized
    assert label in tags(name)
    entity = log('x.' + name)
    assert label in {(r['category'], r['subtype']) for r in entity['taxonomy_labels']}
    result = classify_text(name + '="<redacted>"')
    assert label in {(r['category'], r['subtype']) for r in result['matches']}
    assert all(r['candidate_status'] == 'placeholder_or_example' for r in result['matches'])


@pytest.mark.parametrize('name', ['APIKeyCount', 'APIKEYCount', 'IPAddressCount', 'HTTPAuthorizationCount', 'HTTPHeadersCount'])
def test_aggregate_cannot_be_revived_by_legacy_rule(name):
    assert tags(name) == set()
    assert _types(name) == set()
    for expression in (name, 'x.' + name):
        entity = log(expression)
        assert entity['data_types'] == []
        assert entity['taxonomy_labels'] == []
        assert entity['unknown_type_review']['needs_review']


@pytest.mark.parametrize('expression, expected', [
    ('APIKey.id', set()), ('password.name', set()),
    ('password.user.id', {('QID', 'user_identifier')}),
    ('user.ID', {('QID', 'user_identifier')}),
    ('user.Name', {('PII', 'person_name')}),
    ('password["user"]["ID"]', {('QID', 'user_identifier')}),
    ('APIKey().id', set()), ('cache.ID', set()), ('repo.Name', set()),
    ('APIKey . id', set()), ('password[ "name" ]', set()),
    ('user.undocumented_field', set()),
])
def test_projection_only_matches_the_final_field(expression, expected):
    assert tags(expression) == expected
    assert 'credential' not in _types(expression)
    if expression == 'APIKey().id':
        return  # The parser separately preserves unknown call semantics.
    entity = log(expression)
    assert {(r['category'], r['subtype']) for r in entity['taxonomy_labels']} == expected
    if not expected:
        assert entity['unknown_type_review']['needs_review']


def test_constant_get_uses_the_same_normalized_field_context():
    entity = log('user.get("ID")')
    assert {(r['category'], r['subtype']) for r in entity['taxonomy_labels']} == {('QID', 'user_identifier')}


def test_explicit_parent_helper_is_bounded_and_does_not_match_parent_alone():
    assert field_subject('ID', 'user') == ('user_id', 5)
    assert tags('ID', parent='user') == {('QID', 'user_identifier')}
    assert tags('Name', parent='user') == {('PII', 'person_name')}
    assert tags('ID', parent='APIKey') == set()
    assert tags('name', parent='password') == set()
    assert tags('unknown', parent='user') == set()
    assert tags('body', parent='body') == {('BIZ', 'business_object')}
    for projected in ('APIKey.id', 'password.name', 'user.metadata.id', 'APIKey.id()'):
        assert tags(projected, parent='wrapper') == tags(projected) == set()


def test_legacy_prompt_query_hints_remain_available():
    assert 'content_visibility_unknown' in _types('prompt')
    assert 'opaque_object' in _types('query')
    assert 'credential' not in _types('password.query')


def test_known_output_does_not_remove_unknown_sibling():
    entity = log('{"HTTPAuthorization": x, "other": user.undocumented_field}')
    assert ('AUTH', 'authorization_header') in {(r['category'], r['subtype']) for r in entity['taxonomy_labels']}
    assert entity['unknown_type_review']['needs_review']
    assert 'user.undocumented_field' in entity['unknown_type_review']['unclassified_sources']


@pytest.mark.parametrize('expression', ['APIKey.id()', 'password.get_name()'])
def test_empty_call_notation_does_not_reintroduce_receiver_types(expression):
    from agentlog_unified.structured_types import classify_structured
    import json
    assert not tags(expression)
    assert not _types(expression)
    for value in (expression, '{' + repr(expression) + ': x}'):
        entity = log(value)
        assert not entity['taxonomy_labels']
        assert entity['unknown_type_review']['needs_review']
    result = classify_structured(json.dumps({expression: 'fixture-shaped-value'}))
    assert not result['matches']
    assert result['counts']['unknown_nodes'] > 0
    assert tags('get_password()') == {('AUTH', 'password')}
