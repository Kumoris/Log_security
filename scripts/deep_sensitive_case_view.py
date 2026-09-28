import sys,re,json
import sensitive_log_review as s
from annotate_sensitive_log_review import safe_excerpt
wanted={int(x) for x in sys.argv[1:]};ee,src,links,ctx=s.load();es={x['modification_id']:x for x in ee}
for q in s.read(s.OUT/'review_queue.jsonl'):
 if q['queue_index'] not in wanted:continue
 e=es[q['modification_id']];print('\nDEEP',q['queue_index'],e['modification_id'],e['repository'],e['modification_sha'],e['file_path'])
 print('BEFORE',s.redact(e['current_observation'].get('before_statement'),True));print('AFTER',s.redact(e['current_observation'].get('after_statement'),True))
 for d in e['current_observation']['target_diff_excerpts']:
  print('DIFF',d['diff_basis_sha'],d['diff_target_sha'],d['path'])
  for row in d['rows']:print(row['tag'],row['old_line'],row['new_line'],s.redact(row['text'],True))
 seen=set()
 for l in links[e['modification_id']]:
  v=src[l['evidence_id']]
  if v['equivalence_group'] in seen or v['source_type']=='prompt':continue
  seen.add(v['equivalence_group']);text=v['text'];hits=list(re.finditer(r'(?i)redact|saniti[sz]|sensitive|privacy|secret|credential|userinfo|synthetic|publicId',text))
  if not hits and v['source_type'] not in ('commit_message','pr_description'):continue
  spans=[(max(0,h.start()-60),min(len(text),h.end()+250)) for h in hits[:4]] or [(0,min(len(text),600))]
  print('SOURCE',v['evidence_id'],v['source_type'],v.get('source_url'), 'RELATION',l['relation'])
  for a,b in spans:
   quote=safe_excerpt(v,a,b);print('EXCERPT',quote['original_start'],quote['original_end'],quote['quote_redacted'])
