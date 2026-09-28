from batch_swechat_followups import run
from run_swechat_followups import *
if __name__=='__main__':
    scope={r['repository']:r['eligible_commits'] for r in json.loads((OUT/'collected_history_scope.json').read_text(encoding='utf-8'))}
    inv=json.loads((OUT/'inventory.json').read_text(encoding='utf-8'))
    for row in sorted(inv['repositories'],key=lambda r:scope.get(r['repository'],0)):
        p=OUT/'repositories'/row['repository'].replace('/','--')
        if (p/'summary.json').exists() or (p/'execution.lock').exists():continue
        print(*run(row),flush=True)
