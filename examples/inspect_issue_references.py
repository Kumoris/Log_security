"""Private-source reading aid: hides values/code blocks, reports truncation."""
import argparse,json,re
from pathlib import Path
from agentlog_unified.storage import redact

ROOT=Path(__file__).resolve().parents[1]/'research/issue-reference-20260910/private'

def safe(text):
    text=re.sub(r'\{code[^}]*\}.*?\{code\}|\{noformat\}.*?\{noformat\}|```.*?```',lambda m:' [CODE BLOCK WITHHELD '+str(len(m.group()))+' chars] ',text or '',flags=re.S)
    text=redact(text)
    text=re.sub(r'(?is)(<(?:password|secret|token)[^>]*>).*?(</(?:password|secret|token)>)',r'\1[VALUE WITHHELD]\2',text)
    text=re.sub(r'(?im)^.*(?:simple authentication\s*:|["\'](?:key|password|secret|token)["\']\s*:).*$','[VALUE LINE WITHHELD]',text)
    text=re.sub(r'(?<![A-Za-z])[A-Za-z0-9+/=_-]{45,}(?![A-Za-z])','[OPAQUE TOKEN WITHHELD]',text)
    return text

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--offset',type=int,default=0);p.add_argument('--count',type=int,default=8);p.add_argument('--keys',nargs='*');p.add_argument('--chars',type=int,default=1100);a=p.parse_args()
 files=sorted(ROOT.glob('*.json'));files=[p for p in files if p.stem in a.keys] if a.keys else files[a.offset:a.offset+a.count]
 for path in files:
  r=json.loads(path.read_text());issue=r['issue_payload'];f=issue.get('fields',issue)
  print('\nISSUE',r['issue'],f.get('summary',f.get('title')),'STATUS',(f.get('status') or {}).get('name',f.get('state')),'RESOLUTION',(f.get('resolution') or {}).get('name'),'FIX', [v['name'] for v in f.get('fixVersions',[])])
  text=safe(f.get('description',f.get('body','')) or '');print('D',text[:a.chars],f'[TRUNCATED {len(text)}]' if len(text)>a.chars else '')
  for c in r['comments']:
   t=safe(c['body'])
   if 'Review Comment:' in t:t=t.split('Review Comment:',1)[1]
   if re.search(r'overall|Here are the results of testing|This message is automatically generated',t) and not re.search(r'sensitiv|password|redact|confidential',t,re.I):t='[CI-only comment retained in private source]'
   print('C'+str(c['id']),t[:a.chars],f'[TRUNCATED {len(t)}]' if len(t)>a.chars else '')
  print('ATTACHMENTS',[(x['id'],x['filename'],x.get('size')) for x in f.get('attachment',[])])
  urls=set(re.findall(r'https?://[^\s<>\]}]+',(f.get('description',f.get('body','')) or '')+'\n'+'\n'.join(c['body'] for c in r['comments'])))
  print('LINKS',[u for u in sorted(urls) if any(s in u for s in ['/commit/','/pull/','git-wip','viewvc','/revision/'])])
