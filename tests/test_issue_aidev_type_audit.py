"""Reference sensitivity must not become target gold or fill missing type counts."""
from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('issue_aidev_audit',
    Path(__file__).resolve().parents[1]/'examples/audit_issue_aidev_types.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_reference_link_preserves_scope_unknown_types_and_null_counts():
    references = [
        {'id': 'password-case', 'human_annotation': {'origin': 'human', 'label': 'sensitive_information'},
         'type_proposals': [{'concept': 'password', 'category': 'AUTH', 'subtype': 'password'}]},
        {'id': 'generic-case', 'human_annotation': {'origin': 'human', 'label': 'sensitive_information'},
         'type_proposals': [{'concept': 'record_payload', 'category': 'BIZ', 'subtype': None}]},
        {'id': 'link-only-case', 'human_annotation': {'origin': 'human', 'label': 'sensitive_information'},
         'type_proposals': []}]
    inventory = [
        {'dataset': 'aidev', 'category': 'AUTH', 'subtype': 'password', 'observation_scope': 'dataset_text_reconciled',
         'count_within_processed_scope': 12, 'application_log_evidence': False},
        {'dataset': 'aidev', 'category': 'AUTH', 'subtype': 'password', 'observation_scope': 'dataset_commit_changes',
         'count_within_processed_scope': None, 'evaluation_status': 'not_evaluated'},
        {'dataset': 'aidev', 'category': 'BIZ', 'subtype': 'request_body', 'count_within_processed_scope': 4}]
    before = deepcopy((references, inventory))
    links, concepts = module.link_types(references, inventory)
    assert (references, inventory) == before
    assert links[0]['human_sensitive_reference_ids'] == ['password-case']
    assert links[0]['application_log_evidence'] is False
    assert links[1]['count_within_processed_scope'] is None
    assert links[2]['reference_concepts'] == []  # payload does not imply arbitrary request bodies
    assert all(r['target_human_confirmed'] is False for r in links)
    assert {c['concept'] for c in concepts} == {'password', 'record_payload'}
    bad = deepcopy(references); bad[0]['human_annotation']['origin'] = 'model'
    with pytest.raises(ValueError, match='reference_not_human_sensitive'):
        module.link_types(bad, inventory)
    with pytest.raises(ValueError, match='non_aidev'):
        module.link_types(references, [{**inventory[0], 'dataset': 'other'}])


def test_evidence_export_keeps_coordinates_without_values_or_value_hashes(tmp_path):
    row = {'id': 'occurrence', 'category': 'AUTH', 'subtype': 'password', 'source_row': 3,
           'column_name': 'body', 'start': 10, 'end': 25, 'candidate_status': 'named_value_candidate',
           'observation_scope': 'dataset_text_reconciled', 'statement': 'SYNTHETIC_SECRET',
           'value': 'SYNTHETIC_SECRET', 'text_hmac_sha256': 'SYNTHETIC_VALUE_HASH'}
    sample = module.safe_sample(row, row, tmp_path/'source.jsonl', 2, 'fixture', 'file-hash')
    assert sample['source_row'] == 3 and sample['start'] == 10
    assert sample['source_record_line'] == 2 and sample['source_file_sha256'] == 'file-hash'
    assert 'SYNTHETIC_SECRET' not in str(sample) and 'SYNTHETIC_VALUE_HASH' not in str(sample)
    assert sample['history_read'] == 'not_git_evidence'
    assert not sample['target_human_confirmed'] and not sample['runtime_confirmed']
    assert module.run(tmp_path, tmp_path/'missing', tmp_path/'out', dry_run=True)['files_written'] is False
    assert not (tmp_path/'out').exists()


def test_same_log_type_with_two_evidence_paths_counts_once():
    row = {'observation_scope': 'dataset_commit_changes', 'taxonomy_labels': [
        {'category': 'BIZ', 'subtype': 'document_content', 'evidence_status': 'carrier_candidate', 'evidence_basis': ['local_assignment']},
        {'category': 'BIZ', 'subtype': 'document_content', 'evidence_status': 'carrier_candidate', 'evidence_basis': ['one_hop']}]}
    assert module.observation_labels(row) == [{'category': 'BIZ', 'subtype': 'document_content',
        'evidence_status': 'carrier_candidate', 'evidence_basis': ['local_assignment', 'one_hop']}]
