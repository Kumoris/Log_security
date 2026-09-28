"""Development equivalence oracle on small guard-approved real Python snapshots."""
from run_swechat_followups import *
from align_swechat_agent_logs import Guard
from agentlog_unified import detector,analysis,matching
from swechat_matching_cache import install as install_matching
from swechat_exact_detection_cache import install as install_exact
from swechat_python_mutation_index import install as install_index
from swechat_python_evaluation_cache import install as install_cache


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--file-cache',action='store_true');ap.add_argument('--accessed-imports',action='store_true');ap.add_argument('--output',type=Path);args=ap.parse_args()
    guard=Guard(PROJECT);seen=set();reports=[];skipped=Counter()
    dest=args.output or OUT/'verification/actual_python_cache_oracle.json'
    if dest.exists():raise FileExistsError(dest)
    for candidate in inputs():
        repo,sha=candidate['repo_id'],candidate['commit_sha']
        key=repo,sha
        if not candidate['path'].endswith('.py') or key in seen:continue
        seen.add(key)
        directory=repository_output_directory(repo)
        if not (directory/'summary.json').exists():continue
        if not guard.api.assess([dict(repository=repo,path=candidate['path'],callee=candidate['callee'])],guard.ids,guard.keys)['allowed']:
            skipped['guard_metadata']+=1;continue
        collection=json.loads((OUT/'collection'/(repo.replace('/','--')+'.json')).read_text(encoding='utf-8'))
        if collection['status']!='fetched':continue
        path=resolve_path(collection['path'])
        tree=git(path,['ls-tree','-r','--long',sha]) or ''
        selected=[]
        for line in tree.splitlines():
            metadata,name=line.split('\t',1);parts=metadata.split()
            if name.endswith('.py') and parts[1]=='blob':selected.append((name,int(parts[3])))
        if not selected or len(selected)>8 or sum(size for _,size in selected)>25000:continue
        if not all(guard.check_path(repo,name) for name,_ in selected):
            skipped['guard_path']+=1;continue
        files={name:git(path,['show',sha+':'+name]) for name,_ in selected}
        if not all(source is not None and guard.check(repo,name,source)=='allowed' for name,source in files.items()):
            skipped['guard_source_or_unavailable']+=1;continue
        baseline=detector.detect_snapshot(files,['python'])
        if not guard.api.assess([{'callee':e['callee']} for e in baseline['entities']],guard.ids,guard.keys)['allowed']:
            skipped['guard_callee']+=1;continue
        expected_matching=[(matching.entity_key(e),matching.behavior(e)) for e in baseline['entities']]
        finish_exact=install_exact(detector)
        finish_index=install_index(detector);finish_cache=install_cache(detector)
        finish_matching=install_matching(analysis,matching)
        finish_files=None
        if args.file_cache:
            from swechat_python_file_cache import install as install_files
            finish_files=install_files(detector,accessed_imports=args.accessed_imports)
        try:
            actual=detector.detect_snapshot(files,['python'])
            repeated=detector.detect_snapshot(files,['python'])
            actual_matching=[(matching.entity_key(e),matching.behavior(e)) for e in actual['entities']]
        finally:
            matching_stats=finish_matching()
            file_stats=finish_files() if finish_files else None
            stats=finish_cache();finish_index();exact_stats=finish_exact()
        reports.append(dict(repository=repo,sha=sha,source_sha256={name:hashlib.sha256(source.encode()).hexdigest() for name,source in files.items()},
            guard_status='allowed',python_files=len(files),entities=len(baseline['entities']),
            complete_output_equal=actual==baseline==repeated and expected_matching==actual_matching,cache_stats=stats,file_cache_stats=file_stats,matching_cache_stats=matching_stats,exact_cache_stats=exact_stats))
        if len(reports)>=3:break
    passed=len(reports)==3 and all(r['complete_output_equal'] for r in reports)
    dump(dest,dict(status='PASS' if passed else 'FAIL',scope='Three small real development snapshots; not held-out accuracy evaluation',
        guards=dict(guard.calls),skipped=dict(skipped),snapshots=reports))
    print(json.dumps(dict(status='PASS' if passed else 'FAIL',snapshots=len(reports),entities=sum(r['entities'] for r in reports))))
    return 0 if passed else 1


if __name__=='__main__':sys.exit(main())
