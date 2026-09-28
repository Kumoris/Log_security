"""Hash raw prompt-join inputs before stage3, without reading case content."""
from run_swechat_followups import *
from agent_log_motivation_v11 import file_hash
from datetime import datetime, timezone

if __name__ == '__main__':
    output = OUT / 'raw_stage3_input_baseline.json'
    if output.exists():
        raise RuntimeError('Raw input baseline already exists')
    started = datetime.now(timezone.utc).isoformat()
    records = []
    for name in ('commits', 'checkpoints', 'sessions', 'conversations'):
        p = PROJECT/'data/cache/swechat-frozen' / (name + '.parquet')
        records.append(dict(path=str(p), bytes=p.stat().st_size, sha256=file_hash(p)))
    dump(output, dict(started_at=started, finished_at=datetime.now(timezone.utc).isoformat(),
                      scope='Raw files before stage3; the older accepted baseline separately verifies commits from before this task',
                      source_content_displayed=False, files=records))
    print('Hashed', len(records), 'raw input tables', flush=True)
