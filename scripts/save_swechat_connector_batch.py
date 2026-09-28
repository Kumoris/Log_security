"""Persist actual GET tool results only for association-derived planned URLs."""
import json
import sys
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

ROOT=Path(__file__).resolve().parents[1]/'outputs/swechat_followup_20260922/connector_collection'


def save(batch, root=ROOT):
    allowed={r['url']:r for r in (json.loads(line) for line in (root/'requests.jsonl').read_text(encoding='utf-8').splitlines() if line)}
    counts={'success':0,'failure':0,'already_saved':0}
    for row in batch:
        url=row['url']
        if url not in allowed or urlparse(url).netloc!='api.github.com' or urlparse(url).scheme!='https':
            raise ValueError('Unplanned or non-GitHub request')
        key=hashlib.sha256(url.encode()).hexdigest()
        collected=row.get('collected_at') or datetime.now(timezone.utc).isoformat()
        if row['success']:
            if not isinstance(row.get('data'),(dict,list)):
                raise ValueError('Non-JSON GitHub response')
            dest=root/'external_cache'/(key+'.json')
            payload=dict(url=url,collected_at=collected,headers={},data=row['data'],
                         acquisition_method='connected_github_fetch_GET',request_association=allowed[url]['association_basis'])
            if allowed[url]['paginated'] and isinstance(row['data'],list) and len(row['data'])==100:
                parsed=urlparse(url);query=dict(parse_qsl(parsed.query))
                query['page']=str(int(query.get('page','1'))+1)
                payload['connector_adapter']=dict(next_url=urlunparse(parsed._replace(query=urlencode(query))),
                    pagination_basis='full_100_row_page_request_next_explicitly',server_headers_available=False)
            kind='success'
        else:
            dest=root/'failures'/(key+'.json')
            payload=dict(url=url,collected_at=collected,error_type=row.get('error_type','connector_read_failed'),
                         reason=row['reason'],retryable=row.get('retryable',True),
                         acquisition_method='connected_github_fetch_GET',request_association=allowed[url]['association_basis'])
            kind='failure'
        dest.parent.mkdir(parents=True,exist_ok=True)
        if dest.exists():
            counts['already_saved']+=1
            continue
        with dest.open('x',encoding='utf-8') as f:json.dump(payload,f,ensure_ascii=False)
        counts[kind]+=1
    return counts


if __name__=='__main__':
    print(json.dumps(save(json.load(sys.stdin))))
