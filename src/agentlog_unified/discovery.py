"""Bounded GitHub search discovery, separate from outcome-based screening."""
from datetime import date, timedelta
from urllib.parse import urlencode
import re


def discover_prs(client, queries, start, end, max_partitions=100):
    start, end = date.fromisoformat(start), date.fromisoformat(end)
    if start > end or max_partitions < 1:
        raise ValueError("Invalid discovery dates or partition budget")
    if not queries or any(not q.strip() or re.search(r'\bcreated:', q) for q in queries):
        raise ValueError("Provide search queries without created:; use --since/--until")
    rows, partitions = {}, []
    pending = [(q, start, end) for q in queries]
    while pending and len(partitions) < max_partitions:
        q, a, b = pending.pop(0)
        query = f"{q} is:pr created:{a.isoformat()}..{b.isoformat()}"
        data = client.get('/search/issues?' + urlencode({'q': query, 'per_page': 100, 'page': 1}))
        if not isinstance(data, dict) or not isinstance(data.get('items'), list):
            partitions.append({'query': query, 'status': 'unavailable', 'returned': 0})
            continue
        total = int(data.get('total_count', 0))
        if total > 1000 and a < b:
            mid = a + (b-a)//2
            pending[:0] = [(q, a, mid), (q, mid+timedelta(days=1), b)]
            partitions.append({'query': query, 'status': 'split', 'total': total})
            continue
        items = list(data['items'])
        status = 'partial' if total > 1000 or data.get('incomplete_results') else 'complete'
        for page in range(2, min(10, (total+99)//100)+1):
            more = client.get('/search/issues?' + urlencode({'q': query, 'per_page': 100, 'page': page}))
            if not isinstance(more, dict) or not isinstance(more.get('items'), list):
                status = 'partial'; break
            items.extend(more['items'])
            if more.get('incomplete_results'):
                status = 'partial'
        if len(items) < min(total, 1000):
            status = 'partial'
        unique_urls={item.get('html_url') for item in items if re.fullmatch(
            r'https://github.com/[^/]+/[^/]+/pull/\d+',str(item.get('html_url','')))}
        if len(unique_urls)<min(total,1000):
            status='partial'
        partitions.append({'query': query, 'status': status, 'returned': len(items),
                           'unique_prs':len(unique_urls), 'total': total})
        for item in items:
            url = item.get('html_url', '')
            match = re.fullmatch(r'https://github.com/([^/]+/[^/]+)/pull/(\d+)', url)
            if not match:
                continue
            row = rows.setdefault(url, {'repository': match[1], 'pr_number': int(match[2]), 'pr_url': url,
                'pr_actor_type': 'unknown', 'metadata_source': 'github_search', 'cohort': 'primary_cohort',
                'discovery_queries': [], 'provenance_evidence': []})
            row['discovery_queries'].append(query)
            row['provenance_evidence'].append({'kind': 'search_result_clue', 'url': url,
                'query': query, 'partition_status': status, 'verified': False})
    partitions.extend({'query': q, 'start': a.isoformat(), 'end': b.isoformat(),
                       'status': 'budget_exceeded'} for q, a, b in pending)
    return {'prs': list(rows.values()), 'partitions': partitions,
            'complete': all(p['status'] in {'complete', 'split'} for p in partitions),
            'selection': 'configured_search_not_random_sample', 'requests': client.requests}
