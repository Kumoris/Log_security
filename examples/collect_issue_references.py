"""Read-only anonymous public issue collection with complete comment pagination.

Raw source responses stay private. Nothing from target repositories is executed.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import urllib.request
from urllib.parse import urlsplit

from agentlog_unified.config import now, sha256_file
from agentlog_unified.storage import atomic_write


def collect(annotation, output):
    issue_url=annotation['issue_url']; github='github.com' in issue_url
    key='Azure-azure-cli-23740' if github else issue_url.rsplit('/',1)[-1]
    dest=output/'private'/f'{key}.json'
    if dest.exists():
        old=json.loads(dest.read_text())
        if old.get('complete'):return {'issue':key,'status':'cached','comments':len(old['comments'])}
    receipts=[]
    def get(url):
        receipt={'url':url,'fetched_at':now()}
        try:
            req=urllib.request.Request(url,headers={'User-Agent':'agentlog-issue-reference-audit/0.8.1','Accept':'application/json'})
            with urllib.request.urlopen(req,timeout=30) as response:
                raw=response.read(12*1024*1024+1)
                if len(raw)>12*1024*1024:raise ValueError('response_budget_exceeded')
                receipt.update(status=response.status,bytes=len(raw),server_date=response.headers.get('Date'))
                payload=json.loads(raw)
        except Exception as exc:
            receipt.update(error=type(exc).__name__,status=getattr(exc,'code',None));receipts.append(receipt);raise
        receipts.append(receipt);return payload
    artifact={'issue':key,'source_annotation_id':annotation['id'],'issue_url':issue_url,'complete':False,'receipts':receipts,'comments':[]}
    try:
        if github:
            api='https://api.github.com/repos'+urlsplit(issue_url).path
            issue=get(api);artifact['issue_payload']=issue
            page=1
            while True:
                comments=get(api+'/comments?per_page=100&page='+str(page));artifact['comments']+=comments
                if len(comments)<100:break
                page+=1
            if len(artifact['comments'])<issue['comments']:raise ValueError('comments_incomplete')
            # Linked PRs / closure events remain source claims until their patches are read.
            artifact['timeline']=get(api+'/timeline?per_page=100')
            artifact['timeline_complete']=len(artifact['timeline'])<100
        else:
            api='https://issues.apache.org/jira/rest/api/2/issue/'+key
            issue=get(api);artifact['issue_payload']=issue
            start=0
            while True:
                page=get(api+'/comment?startAt='+str(start)+'&maxResults=100')
                artifact['comments']+=page['comments'];start+=len(page['comments'])
                if start>=page['total']:break
                if not page['comments']:raise ValueError('comments_incomplete')
        artifact['complete']=True
    except Exception as exc:artifact['failure']=type(exc).__name__
    atomic_write(dest,json.dumps(artifact,ensure_ascii=False))
    return {'issue':key,'status':'complete' if artifact['complete'] else 'failed','comments':len(artifact['comments']),
            'raw_sha256':sha256_file(dest),'requests':len(receipts)}


def main():
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    output=Path(a.output);output.mkdir(parents=True,exist_ok=True)
    source=Path(a.input);rows=[json.loads(s) for s in source.read_text().splitlines() if s]
    results=[]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures=[pool.submit(collect,r,output) for r in rows]
        for f in as_completed(futures):
            r=f.result();results.append(r);print(json.dumps(r),flush=True)
    atomic_write(output/'collection.json',json.dumps({'input_sha256':sha256_file(source),'cases':sorted(results,key=lambda r:r['issue']),
        'denominator':len(rows),'read_only':True,'target_code_executed':False,'model_api_calls':0},indent=2))

if __name__=='__main__':main()
