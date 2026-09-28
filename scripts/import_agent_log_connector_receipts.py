"""Import unmodified read-only connector batches into v1.1-compatible caches.

Receipts are URL-bound and append-only. A batch contains the exact tool JSON
response, fetch time and the association that led to its request. No network.
"""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from agent_log_motivation_v11 import write_json, file_hash


def ingest(batches, output):
    out=Path(output);out.mkdir(parents=True,exist_ok=False)
    cache=out/'external_cache';cache.mkdir()
    failures=out/'failures';failures.mkdir()
    known={};counts={'success':0,'failure':0,'duplicate_identical_receipts':0}
    for p in sorted(Path(batches).glob('batch-*.json')) + sorted(Path(batches).glob('retry_*.json')):
        batch_hash=file_hash(p)
        payload_rows=json.loads(p.read_text(encoding='utf-8'))
        for row in (payload_rows if isinstance(payload_rows,list) else [payload_rows]):
            url=row['url'];u=urlparse(url)
            if u.scheme!='https' or u.netloc!='api.github.com' or not u.path.startswith('/repos/') or not row.get('association_basis'):
                raise ValueError('invalid_association_or_url')
            key=hashlib.sha256(url.encode()).hexdigest()
            if url in known:
                if known[url] == row:
                    counts['duplicate_identical_receipts']+=1;continue
                if known[url]['success'] or not row['success']:
                    raise ValueError('conflicting_receipts_for_same_url')
                # A successful retry adds a success cache; original failure remains.
            known[url]=row
            common=dict(url=url,collected_at=row['collected_at'],acquisition_method='connected_github_fetch_GET',
                        request_association=row['association_basis'],raw_receipt_path=str(p.resolve()),raw_receipt_sha256=batch_hash)
            if row['success']:
                if not isinstance(row.get('data'),(dict,list)):raise ValueError('invalid_json_response')
                payload=dict(**common,headers={},data=row['data'])
                if row.get('paginated') and isinstance(row['data'],list) and len(row['data'])==100:
                    query=dict(parse_qsl(u.query));query['page']=str(int(query.get('page','1'))+1)
                    payload['connector_adapter']=dict(next_url=urlunparse(u._replace(query=urlencode(query))),
                        pagination_basis='full_100_row_page_request_next_explicitly',server_headers_available=False)
                dest=cache/(key+'.json');counts['success']+=1
            else:
                payload=dict(**common,error_type=row.get('error_type','connector_read_failed'),reason=row['reason'],retryable=True)
                dest=failures/(key+'.json');counts['failure']+=1
            write_json(dest,payload)
    counts['unique_urls']=len(known)
    counts['unique_successful_urls']=sum(r['success'] for r in known.values())
    counts['unique_unavailable_urls']=sum(not r['success'] for r in known.values())
    write_json(out/'summary.json',counts)
    print(json.dumps(counts),flush=True)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--batches',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();ingest(args.batches,args.output)
