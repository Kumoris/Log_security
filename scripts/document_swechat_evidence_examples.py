"""Export traceable examples from actual, guard-verified main-data results."""
from run_swechat_followups import *
from agent_log_motivation_v11 import rows, file_hash


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--stage3-name', default='stage3')
    args = ap.parse_args()
    source = OUT / args.stage3_name
    dest = OUT / ('examples-' + args.stage3_name)
    dest.mkdir(exist_ok=False)
    events = [e for _, e in rows(source / 'log_modifications.jsonl') if e['guard_status'] == 'allowed']
    evidence = {e['evidence_id']: e for _, e in rows(source / 'motive_evidence.jsonl')}
    motives = {e['event_id']: e for _, e in rows(source / 'motives.jsonl')}
    links = defaultdict(list)
    for _, link in rows(source / 'evidence_links.jsonl'):
        links[link['event_id']].append(link)
    checks = [
        ('direct_call_change', lambda e: e.get('change_relation') == 'direct_call_change'),
        ('dependency_change', lambda e: e.get('change_relation') == 'dependency_change'),
        ('mixed_file', lambda e: any('mixed' in str(a.get('file_attribution_labels')) for a in e.get('stage1_attribution', []))),
        ('multiple_source_types', lambda e: len({x['source_type'] for x in links[e['event_id']]}) >= 2),
    ] + [(s, lambda e, s=s: motives[e['event_id']]['motive_status'] == s)
         for s in ('explicit', 'inferred', 'unknown', 'conflicting')]
    selected = []
    availability = []
    for kind, predicate in checks:
        candidates = [e for e in events if predicate(e)]
        availability.append(dict(category=kind, actual_available_rows=len(candidates)))
        if not candidates:
            continue
        event = max(candidates, key=lambda e: len({x['source_type'] for x in links[e['event_id']]}))
        selected.append(dict(category=kind, modification=event, motive=motives[event['event_id']],
                             evidence_chain=[dict(link=l, source=evidence[l['evidence_id']])
                                             for l in links[event['event_id']]]))
    jl(dest / 'examples.jsonl', selected)
    dump(dest / 'availability.json', availability)
    lines = ['# 主数据可追溯样例', '',
             '样例按已经核验的输出选择，不作为准确率抽样。没有实际样例的动机状态不构造示例。', '']
    for row in selected:
        e, m = row['modification'], row['motive']
        lines += ['## ' + row['category'], '',
                  f"- 事件 ID：`{e['event_id']}`；第一步 ID：`{json.dumps(e['stage1_log_ids'])}`。",
                  f"- 仓库：`{e['repository']}`；文件：`{e['file_path']}`。",
                  f"- 初始提交：`{e['introduction_sha']}`；修改父提交：`{e['parent_sha']}`；修改提交：`{e['modification_sha']}`。",
                  f"- 原始第二步位置：`{e['input_path']}` 第 {e['input_row']} 行。",
                  f"- 动机状态：`{m['motive_status']}`；原因：`{m['unknown_reason']}`。", '',
                  '观察到的代码变化（不是修改目的）：', '', '```json',
                  json.dumps(e['observed_change'], ensure_ascii=False, indent=2), '```', '']
        shown_types=set()
        for item in row['evidence_chain']:
            link, ev = item['link'], item['source']
            if ev['source_type'] in shown_types:continue
            shown_types.add(ev['source_type'])
            quotes=list(dict.fromkeys(ref['quote'] for claim in m['claims'] for ref in claim['citations'] if ref['evidence_id']==ev['evidence_id']))
            excerpt='\n…\n'.join(quotes) if quotes else ev['text'][:700]
            lines += [f"证据 `{ev['evidence_id']}`（{ev['source_type']}）：", '',
                      f"- 来源 ID：`{ev['source_id']}`；时间：`{ev['source_time']}`。",
                      f"- URL：{ev['source_url'] or '原始来源未提供'}。",
                      f"- 本地来源：`{ev['source_local_path']}`。",
                      f"- 关联方法：`{link['association_method']}`。", '', '```json',
                      json.dumps(link['association_basis'], ensure_ascii=False, indent=2), '```', '',
                      ('结论引用的必要原文：' if quotes else '上下文节选（未据此确认目的；完整原文和链路见同目录 JSONL）：'), '',
                      *['> ' + part for part in excerpt.splitlines()], '']
        lines += ['结论审核：', '', '```json', json.dumps(m, ensure_ascii=False, indent=2), '```', '']
    (dest / 'README.md').write_text('\n'.join(lines), encoding='utf-8')
    dump(dest / 'manifest.json', dict(source_stage3_manifest_sha256=file_hash(source / 'manifest.json'),
                                    artifacts={p.name: file_hash(p) for p in dest.iterdir() if p.is_file()}))
    print(dest, flush=True)


if __name__ == '__main__':
    main()
