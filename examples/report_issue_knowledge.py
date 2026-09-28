"""Verify the frozen 2026-09-10 pilot; no source fetch or model execution."""
from collections import Counter
import json
from pathlib import Path
import shutil

from agentlog_unified.config import sha256_file
from agentlog_unified.export import write_json, write_csv, write_jsonl

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT/'docs/issue-knowledge-20260910'
DEST.mkdir(parents=True, exist_ok=True)


def read(path): return json.loads(path.read_text())
def rows(path): return [json.loads(s) for s in path.read_text().splitlines() if s]


verified = {}
for name in ('issue-knowledge-scoped-20260910','issue-knowledge-offline-20260910','issue-knowledge-model-20260910',
             'issue-knowledge-synthetic-scan-20260910'):
    folder = ROOT/'outputs/semantic-runs'/name; manifest = read(folder/'manifest.json')
    assert manifest['status']=='complete'
    artifacts = manifest.get('artifacts', manifest.get('artifact_sha256'))
    for relative, expected in artifacts.items(): assert sha256_file(folder/relative)==expected
    sources = manifest['fingerprint'].get('sources', manifest['fingerprint'].get('source_sha256'))
    for filename, expected in sources.items(): assert sha256_file(ROOT/'src/agentlog_unified'/filename)==expected
    verified[name] = {'artifacts_verified':len(artifacts),'sources_verified':len(sources)}

knowledge = ROOT/'outputs/semantic-runs/issue-knowledge-scoped-20260910'
annotations = rows(knowledge/'issue_annotations.jsonl')
programs = rows(knowledge/'program_knowledge_candidates.jsonl')
source = ROOT/'data/semantic-inputs/issue-report-human-20260910/source-google-doc.json'
assert source.stat().st_mode & 0o777 == 0o600
snapshot = read(source)
report = {'source':{'url':'https://docs.google.com/document/d/'+snapshot['document']['documentId']+'/edit',
    'document_title':snapshot['document']['title'],'revision':snapshot['document']['revisionId'],
    'modified_time':snapshot['metadata']['modified_time'],'source_sha256':sha256_file(source),
    'tab_count':len(snapshot['document']['tabs']), 'snapshot_permission':'0600', 'remote_document_modified':False},
    'verification':verified, 'issue_import':read(knowledge/'coverage.json'),
    'synthetic':read(ROOT/'outputs/semantic-runs/issue-knowledge-synthetic-scan-20260910/coverage.json'),
    'model':read(ROOT/'outputs/semantic-runs/issue-knowledge-model-20260910/coverage.json'),
    'scope_refinement':{'initial_whole_function_retrieval_cases':76,'final_anchored_retrieval_cases':26,
        'denominator':100,'is_accuracy':False, 'reason':'Removed analogy retrieval triggered by unrelated neighboring variables.'},
    'program_analogies_by_concept':dict(Counter(s['concept'] for r in programs for s in r['knowledge']['suggestions'])),
    'strict_generic_names':{'definition':['data','value','payload'],
        'denominator':sum(r['field'] in {'data','value','payload'} for r in programs),
        'with_analogies':sum(r['field'] in {'data','value','payload'} and bool(r['knowledge']['suggestions']) for r in programs)},
    'source_annotations_are_program_gold':False, 'all_source_material_used_for_development':True,
    'accuracy':None,'recall':None,'new_paid_api_calls':0,'new_actual_model_calls':2,
    'global_model_attempts_before':44,'global_model_attempts_after':46,'global_model_attempt_cap':80,
    'actual_modified_files':['src/agentlog_unified/issue_knowledge.py','src/agentlog_unified/semantic_demand.py',
        'src/agentlog_unified/cli.py','src/agentlog_unified/__init__.py','pyproject.toml','tests/test_issue_knowledge.py'],
    'limits':['No exact original/redacted span pairs or complete negative annotations in the supplied document.',
        'Nearest preceding issue link association is a document-layout heuristic; source issues not fetched.',
        'Human sensitivity labels apply only to selected issue excerpt groups, not subtype or program correctness.',
        '31 explicit phrase concepts and 16 proposed new/split concepts do not establish taxonomy completeness.',
        'Real corpus is the existing frozen 100 uses from 3 repositories; no new real Git history fetched.',
        'Model pilot remains unknown for sensitive type; missing version-bound http.Request.RemoteAddr field definition.',
        'Existing full AIDev schema and account cells not rescanned; source values never reconstructed.',
        'No runtime target code execution, sanitizer-effect confirmation, held-out accuracy or category saturation.']}
assert report['model']['model_attempts_this_run']==2
assert report['model']['global_attempts_used']==46
for stem in ('offline-resume','scoped-resume','model-resume'):
    result = read(Path('/tmp')/('issue-knowledge-'+stem+'.json'))
    assert result['resumed_without_calls']
    report[stem] = {'resumed_without_calls':True}
test_text = Path('/tmp/issue-knowledge-all-tests-final.txt').read_text()
assert '769 passed' in test_text and 'failed' not in test_text
shutil.copyfile('/tmp/issue-knowledge-all-tests-final.txt', DEST/'pytest.txt')
report['tests'] = {'passed':769,'failed':0,'source':'pytest.txt'}
template = [{'annotation_id':r['id'],'issue_url':r['issue_url'],'evidence_sha256':sha256_file(knowledge/'evidence'/(r['id']+'.json')),
    'existing_human_sensitivity':r['human_annotation']['label'], 'status':'pending_human_type_review',
    'semantic_meaning':'','category':'','subtype':'','new_split_merge_decision':'','exact_span_refs':'',
    'issue_link_association_correct':'','annotator':'','rationale':''} for r in annotations]
write_csv(DEST/'human_type_annotation_template.csv',template)
write_jsonl(DEST/'human_type_annotation_template.jsonl',template)
write_json(DEST/'results.json',report)
print(json.dumps({'verified_runs':len(verified),'tests_passed':769,'issue_groups':len(annotations),
    'real_fields':len(programs),'actual_model_calls':2,'accuracy_estimated':False}))
