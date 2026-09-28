"""The reference exporter must fail closed on missing or invented evidence."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('issue_reference_export', ROOT/'examples/export_issue_references.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_reference_validation_rejects_unreliable_provenance():
    annotations = [{'id':'a'}]
    source = {'issue':'T-1','issue_url':'https://issues.apache.org/jira/browse/T-1',
              'source_annotation_id':'a','complete':True,
              'issue_payload':{'fields':{'description':'Sensitive field context.', 'comment':{'total':1}}},
              'comments':[{'id':'1','body':'Counterevidence.'}]}
    decision = {'issue':'T-1','kind':'reported_sensitive_value','reference_answer_zh':'仅限来源声明',
                'review_origin':'assistant_source_adjudication_not_human_expert','evidence_refs':['D','C1']}
    module.validate(annotations,[decision],{'T-1':source})
    assert module.evidence(source,'C1')['json_pointer']=='/comments/0/body'
    bad=copy.deepcopy(decision);bad['evidence_refs']=['C2']
    with pytest.raises(ValueError,match='unresolved evidence'):
        module.validate(annotations,[bad],{'T-1':source})
    bad=copy.deepcopy(source);bad['comments']=[]
    with pytest.raises(ValueError,match='incomplete/duplicate comments'):
        module.validate(annotations,[decision],{'T-1':bad})
    with pytest.raises(ValueError,match='exactly once'):
        module.validate(annotations,[decision,decision],{'T-1':source})
    bad=copy.deepcopy(decision);bad['review_origin']='human_expert'
    with pytest.raises(ValueError,match='unattested review origin'):
        module.validate(annotations,[bad],{'T-1':source})


def test_collected_corpus_provenance_and_scope():
    root=ROOT/'research/issue-reference-20260910'
    if not (root/'private').is_dir():
        pytest.skip('private issue snapshots are not included in minimal distributions')
    annotations=[json.loads(s) for s in (ROOT/'outputs/semantic-runs/issue-knowledge-scoped-20260910/issue_annotations.jsonl').read_text().splitlines() if s]
    decisions=json.loads((root/'adjudications.json').read_text())
    sources={p.stem:json.loads(p.read_text()) for p in (root/'private').glob('*.json')}
    module.validate(annotations,decisions,sources)
    assert len(decisions)==len(annotations)==67
    by={r['issue']:r for r in decisions}
    assert by['JSPWIKI-736']['kind']=='out_of_application_log_scope'
    assert by['ZEPPELIN-828']['kind']=='out_of_application_log_scope'
    assert 'network_address' not in by['Azure-azure-cli-23740']['concepts']
    assert by['CLOUDSTACK-8485']['contextual_negative_examples']
