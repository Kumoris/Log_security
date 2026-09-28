"""Plan read-only connector requests from verified stage-three associations.

Run after stage2 and the initial stage3 export. Connector responses are stored
separately; this never edits either completed stage. No keyword/time joins.
"""
from run_swechat_followups import *
from agent_log_motivation_v11 import rows, issue_refs, digest
from urllib.parse import urlparse, parse_qs, urlencode
import shutil


def plan():
    source = OUT / 'stage3'
    if json.loads((OUT / 'stage2/validation.json').read_text(encoding='utf-8'))['status'] != 'PASS':
        raise RuntimeError('stage2_validation_required')
    if json.loads((source / 'validation.json').read_text(encoding='utf-8'))['status'] != 'PASS':
        raise RuntimeError('initial_stage3_validation_required')
    root = OUT / 'connector_collection'
    cache = root / 'external_cache'
    cache.mkdir(parents=True, exist_ok=True)
    failures = root / 'failures'
    failures.mkdir(exist_ok=True)
    for p in (source / 'external_cache').glob('*.json'):
        dest = cache / p.name
        if not dest.exists():
            shutil.copyfile(p, dest)
    requests = {}
    unavailable = []

    def read(endpoint, basis, paginated=False):
        base = 'https://api.github.com/' + endpoint
        result = []
        for page in range(1, 11 if paginated else 2):
            suffix = ('?per_page=100' + ('&page=' + str(page) if page > 1 else '')) if paginated else ''
            url = base + suffix
            key = digest(url)
            request = dict(url=url, cache_key=key, association_basis=basis, paginated=paginated, page=page)
            requests[url] = request
            p = cache / (key + '.json')
            if not p.exists():
                if (failures / (key + '.json')).exists():
                    unavailable.append(dict(**request, failure_receipt=str(failures / (key + '.json'))))
                return result if paginated else None
            saved = json.loads(p.read_text(encoding='utf-8'))
            if saved['url'] != url:
                raise ValueError('response_cache_url_mismatch')
            data = saved['data']
            if not paginated:
                return data
            if not isinstance(data, list):
                unavailable.append(dict(**request, reason='unexpected_non_list_response'))
                return result
            result.extend(data)
            # The connector does not expose HTTP Link headers. Explicitly read
            # another page whenever a complete 100-row page is returned.
            if len(data) < 100:
                return result
        unavailable.append(dict(url=base, association_basis=basis, reason='pagination_budget_10_pages'))
        return result

    events = [e for _, e in rows(source / 'log_modifications.jsonl') if e['guard_status'] == 'allowed']
    groups = defaultdict(list)
    for e in events:
        groups[(e['repository'], e['modification_sha'])].append(e['event_id'])
    local_messages = {}
    for _, e in rows(source / 'motive_evidence.jsonl'):
        if e['source_type'] == 'commit_message':
            local_messages.setdefault((e['repository'], e['source_id']), set()).add(e['text'])
    for (repo, sha), event_ids in groups.items():
        basis = dict(repository=repo, modification_sha=sha, event_ids=event_ids)
        commit = read(f'repos/{repo}/commits/{sha}', basis)
        messages = list(local_messages.get((repo, sha), set()))
        if isinstance(commit, dict) and commit.get('sha') == sha:
            messages.append((commit.get('commit') or {}).get('message') or '')
        refs = set(ref for message in messages for ref in issue_refs(message, repo))
        prs = read(f'repos/{repo}/commits/{sha}/pulls', basis, True)
        for pr in prs:
            number = pr.get('number')
            if not isinstance(number, int) or (pr.get('base', {}).get('repo') or {}).get('full_name', '').lower() != repo.lower():
                continue
            b = dict(**basis, pr_number=number, association_endpoint=f'repos/{repo}/commits/{sha}/pulls')
            full = read(f'repos/{repo}/pulls/{number}', b)
            if not isinstance(full, dict) or full.get('number') != number:
                continue
            refs.update(issue_refs(full.get('body'), repo))
            for endpoint in (f'pulls/{number}/comments', f'pulls/{number}/reviews', f'issues/{number}/comments'):
                for comment in read(f'repos/{repo}/{endpoint}', b, True):
                    refs.update(issue_refs(comment.get('body'), repo))
        for issue_repo, number in sorted(refs):
            b = dict(**basis, referenced_repository=issue_repo, issue_number=number,
                     association='explicit_reference_in_exact_commit_or_associated_PR_material')
            issue = read(f'repos/{issue_repo}/issues/{number}', b)
            if isinstance(issue, dict) and issue.get('number') == number and not issue.get('pull_request'):
                read(f'repos/{issue_repo}/issues/{number}/comments', b, True)
    pending = [r for r in requests.values() if not (cache / (r['cache_key'] + '.json')).exists()
               and not (failures / (r['cache_key'] + '.json')).exists()]
    jl(root / 'requests.jsonl', requests.values())
    jl(root / 'pending.jsonl', pending)
    jl(root / 'unavailable.jsonl', unavailable)
    dump(root / 'status.json', dict(events=len(events), unique_modification_commits=len(groups),
                                  discovered_requests=len(requests), pending_requests=len(pending),
                                  unavailable_requests=len(unavailable), readonly=True,
                                  pagination='explicit_next_page_on_100_rows_max_10_pages'))
    print(json.dumps(dict(pending=len(pending), discovered=len(requests), unavailable=len(unavailable))), flush=True)


if __name__ == '__main__':
    plan()
