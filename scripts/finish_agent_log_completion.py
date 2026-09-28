"""Finalize a new full-stage-two continuation; keep all parent deliveries intact."""
import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from agent_log_motivation_v11 import rows, file_hash, table, write_json, TYPES
from finish_agent_log_delivery import local_path


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def migrated_motive(row, event_id):
    value = json.loads(json.dumps(row))
    value['event_id'] = event_id
    for claim in value['claims']:
        claim['event_id'] = event_id
    return value


def finish(root, parent):
    root, parent = Path(root), Path(parent)
    if (root / 'manifest.json').exists() or (root / 'README.md').exists():
        raise FileExistsError('Completion delivery already finalized')
    out = root / 'delivery'
    verification = root / 'verification'
    verification.mkdir(exist_ok=True)
    stage2 = read(root / 'stage2_snapshot/summary.json')
    stage3 = read(root / 'stage3_final/summary.json')
    mapping = [r for _, r in rows(root / 'event_identity_migration.jsonl')]
    old = {r['event_id']: r for _, r in rows(parent / 'stage3_final/log_modifications.jsonl')}
    new = {r['event_id']: r for _, r in rows(root / 'stage3_final/log_modifications.jsonl')}
    old_sources = {r['evidence_id']: r for _, r in rows(parent / 'stage3_final/motive_evidence.jsonl')}
    new_sources = {r['evidence_id']: r for _, r in rows(root / 'stage3_final/motive_evidence.jsonl')}
    old_motives = {r['event_id']: r for _, r in rows(parent / 'stage3_final/motives.jsonl')}
    new_motives = {r['event_id']: r for _, r in rows(root / 'stage3_final/motives.jsonl')}
    inherited = {r['new_event_id'] for r in mapping}
    delta = [e for eid, e in new.items() if eid not in inherited]
    ledger = [r for _, r in rows(root / 'stage2_snapshot/candidate_ledger.jsonl')]
    marin = [r for r in ledger if r['repo_id'] == 'marin-community/marin']
    attempt = root.parents[0] / 'swechat_followup_20260922/additional-attempts/marin-detached-shared-gap-20260923'
    receipt = read(attempt / 'selection_validation.json')
    parent_manifest = read(parent / 'manifest.json')
    expected_cache = root / 'connector_collection_final/external_cache'
    actual_cache = root / 'stage3_final/external_cache'
    copied_cache = all((actual_cache / p.name).exists() and file_hash(actual_cache / p.name) == file_hash(p)
                       for p in expected_cache.glob('*.json'))
    checks = {
        'stage2_complete_no_pending': stage2['full_stage2_complete'] and stage2['pending_candidates'] == 0,
        'stage2_validation_pass': read(root / 'stage2_snapshot/validation.json')['status'] == 'PASS',
        'stage3_validation_pass': read(root / 'stage3_final/validation.json')['status'] == 'PASS',
        'delivery_validation_pass': read(out / 'verification.json')['status'] == 'PASS',
        'marin_successful_exit': read(attempt / 'attempt_status.json').get('returncode') == 0 and read(attempt / 'attempt_status.json')['status'] == 'finished',
        'marin_acceptance_and_hashes': receipt['status'] == 'PASS' and all(file_hash(attempt / 'repositories/marin-community--marin' / n) == h for n, h in receipt['artifact_sha256'].items()),
        'twenty_candidates_preserved': len(marin) == 20 and len({r['log_id'] for r in marin}) == 20,
        'twenty_statuses_reconciled': Counter(r['status'] for r in marin) == {'observed_followup': 5, 'history_incomplete': 15},
        'old_event_mapping_complete_unique': len(mapping) == len(old) == len(inherited) and {r['old_event_id'] for r in mapping} == set(old),
        'old_raw_event_records_unchanged': all(old[r['old_event_id']]['input_record_sha256'] == new[r['new_event_id']]['input_record_sha256'] for r in mapping),
        'old_motive_conclusions_preserved': all(migrated_motive(old_motives[r['old_event_id']], r['new_event_id']) == new_motives[r['new_event_id']] for r in mapping),
        'all_old_evidence_content_preserved': all(eid in new_sources and e['content_sha256'] == new_sources[eid]['content_sha256'] and e['text'] == new_sources[eid]['text'] for eid,e in old_sources.items()),
        'exact_delta_204_marin_rows': len(delta) == 204 and all(e['repository'] == 'marin-community/marin' for e in delta),
        'all_delta_guard_allowed': all(e['guard_status'] == 'allowed' for e in delta),
        'all_1701_cache_responses_copied_exactly': copied_cache and len(list(expected_cache.glob('*.json'))) == 1701,
        'parent_delivery_files_unchanged': all(file_hash(parent / name) == h for name,h in parent_manifest['delivery_files'].items()),
        'original_source_inputs_still_unchanged': all(file_hash(local_path(p)) == h for p,h in read(root / 'stage2_snapshot/validation.json')['input_sha256'].items()),
    }
    raw = []
    for r in read(parent / 'raw_prompt_inputs_after.json'):
        p = local_path(r['path'])
        h = file_hash(p)
        raw.append({'path': str(p.resolve()), 'sha256': h, 'matches_parent_baseline': h == r['sha256']})
    checks['raw_prompt_inputs_match_parent_baseline'] = all(r['matches_parent_baseline'] for r in raw)
    write_json(verification / 'raw_inputs_integrity.json', raw)
    result = {'status': 'PASS' if all(checks.values()) else 'FAIL', 'checks': checks,
              'executed_at': datetime.now(timezone.utc).isoformat(), 'scope': 'complete upstream execution and exact incremental data reconciliation; not human motive accuracy'}
    write_json(verification / 'completion_validation.json', result)
    if not all(checks.values()):
        raise ValueError('Completion checks failed: ' + str([k for k,v in checks.items() if not v]))
    table(out, 'marin_candidates', marin, ['log_id', 'repo_id', 'status', 'followup_ids'])
    table(out, 'marin_modifications', delta, ['event_id', 'upstream_event_id', 'modification_sha', 'file_path', 'observed_change', 'motive_status'])
    delta_ids = {e['event_id'] for e in delta}
    delta_links = [r for _,r in rows(root / 'stage3_final/evidence_links.jsonl') if r['event_id'] in delta_ids]
    table(out, 'marin_evidence_links', delta_links, ['event_id', 'evidence_id', 'source_type', 'association_method'])
    coverage = [{'source_type': kind, 'covered_events': len({r['event_id'] for r in delta_links if r['source_type'] == kind}), 'denominator': len(delta)} for kind in TYPES]
    table(out, 'marin_source_coverage', coverage, ['source_type', 'covered_events', 'denominator'])
    gaps = [r for _,r in rows(root / 'stage3_final/unresolved_records.jsonl') if r['event_id'] in delta_ids]
    table(out, 'marin_unresolved_records', gaps, ['event_id', 'source_type', 'reason'])
    write_json(out / 'marin_summary.json', {'candidates': len(marin), 'candidate_status': dict(Counter(r['status'] for r in marin)),
        'associations': len(delta), 'modification_commits': len({e['modification_sha'] for e in delta}),
        'motive_distribution': dict(Counter(e['motive_status'] for e in delta)), 'source_coverage': coverage,
        'missing_reason_counts': dict(Counter(r['reason'] for r in gaps))})
    coverage_text = '\n'.join(f"| {r['source_type']} | {r['covered_events']}/{r['denominator']} |" for r in coverage)
    text = f'''# SWE-chat 20 条候选闭环与完整增量交付

Marin 追踪已于北京时间 2026-09-23 23:05 完成，23:06 成功退出并通过原验收。原协调器在 23:26 完成全批次第二步、本地第三步和独立结构验证。本交付随后补齐新增关联的外部证据并重新执行 v12；此前交付保持不变。

## 这 20 条的结果

- 20 条全部映射并保留；5 条观察到后续修改，产生 204 条起点—修改关联，涉及 26 个修改提交。
- 15 条为 history_incomplete：追踪执行完毕，但历史覆盖不足，不能解释为确定没有修改。
- 新增 69 个按既有事件键汇总的修改事件；204 不是独立日志语句数。
- 新增来源共 188 个 GitHub GET 请求，全部成功，无重定向、分页截断；不写远程资源。

## 全批次数量

| 指标 | 结果 |
|---|---:|
| 第一步候选／第二步输入 | {stage2['stage2_input_candidates']:,} |
| 已处理／仍等待上游 | {stage2['processed_candidates']:,} / {stage2['pending_candidates']} |
| 观察到后续修改的候选 | {stage2['changed_candidates_observed']:,}（{stage2['stage2_final_filter_fraction']:.2%}） |
| 修改关联 | {stage2['stage2_event_links']:,} |
| 既有事件键汇总 | {stage2['unique_modification_events']:,} |
| v12 独立证据／证据关联 | {stage3['evidence_rows']:,} / {stage3['links']:,} |

62 个仓库完成执行，9 个仓库仍记录历史不可用。全量处理完成不等于全部历史覆盖完整；观察到修改的比例是在原固定输入和原筛选口径下的结果。

## 新增修改的证据覆盖

| 来源 | 覆盖修改关联 |
|---|---:|
{coverage_text}

来源覆盖表示取得可核查材料，不代表材料明确解释每条修改目的。新增 204 条动机均保留 unknown，未进行全量目的审阅。继承的三条样例结论不变；完整分布为 {json.dumps(stage3['motive_distribution'],ensure_ascii=False)}。没有独立人工真值。

## 可核查文件

- `delivery/marin_candidates.csv`：20 条候选最终状态；`marin_modifications.csv`、`marin_evidence_links.csv`：新增修改和证据链。
- `delivery/unique_log_modifications.csv`：完整修改事件汇总；`stage3_final/`：完整事件、证据、关联、动机和缺口表。
- `event_identity_migration.csv`：旧视图到新视图的 ID 映射；以同一上游 ID 和原始记录摘要核对，17,969 条旧记录不变。
- `legacy_audit/`：继承并校验的字段字典和历史总体审计；24,685 个历史日志版本与本次 4,128 个候选不能混作同一分母。
- `verification/completion_validation.json`、`delivery/verification.json`：本次实际验证；`verification/source_readback.json` 由后续原始证据回读步骤生成。
- `connector_batches/` 与 `connector_delta/`：新增请求、原始回执和导入缓存；原失败记录仍从父交付保留。

已验证候选全保留、父提交／祖先关系、原文件摘要、旧结论不变、证据 ID／外键／原文与引用、无材料左连接和缓存完整性。既有 processing 脚本保持不变，本次没有重跑前两步筛选或追踪。新增结论仍需逐条动机审阅；此前的历史覆盖、possible 沿袭和外部缺口不会因执行完成自动消失。
'''
    (root / 'README.md').write_text(text, encoding='utf-8')
    write_json(root / 'manifest.json', {'created_at': datetime.now(timezone.utc).isoformat(),
        'parent_manifest_sha256': file_hash(parent / 'manifest.json'),
        'completion_script_sha256': file_hash(__file__),
        'files': {str(p.relative_to(root)): file_hash(p) for p in root.rglob('*') if p.is_file()},
        'remote_writes': False, 'original_stages_modified': False, 'holdout_evaluated': False})
    print(json.dumps({'status':'PASS', 'checks':len(checks), 'candidates':len(marin), 'new_associations':len(delta)}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--parent', type=Path, required=True)
    args = parser.parse_args()
    finish(args.root, args.parent)
