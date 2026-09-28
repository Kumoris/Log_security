"""Run the unmodified PyDriller miner on Linux; guarded analysis remains Windows."""
from run_swechat_followups import *
import gzip,pickle
from agentlog_unified.miner import mine_repository

def windows_path(value):
    value=value.replace('\\','/')
    return Path('/mnt/'+value[0].lower()+value[2:]) if len(value)>2 and value[1]==':' else Path(value)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--repository',required=True);ap.add_argument('--output',required=True);ap.add_argument('--path',required=True);ap.add_argument('--tip',required=True)
    a=ap.parse_args();p=windows_path(a.path);os.environ.update(environment(p))
    import yaml
    config=yaml.safe_load((PROJECT/'config.example.yaml').read_text(encoding='utf-8'))
    from contextlib import ExitStack
    from swechat_native_git_mirror import native_mirror,restore_source_identity
    initials=sorted({r['commit_sha'] for r in inputs() if r['repo_id']==a.repository})
    mirrored=False;mirror_failure=None
    with ExitStack() as stack:
        try:
            acquisition_path,acquisition_env=stack.enter_context(native_mirror(p,[a.tip,*initials],environment))
            mirrored=True
        except Exception as exc:
            acquisition_path,acquisition_env=p,environment(p)
            mirror_failure=type(exc).__name__
        prior_alternates=os.environ.get('GIT_ALTERNATE_OBJECT_DIRECTORIES')
        os.environ.update(acquisition_env)
        if 'GIT_ALTERNATE_OBJECT_DIRECTORIES' not in acquisition_env:os.environ.pop('GIT_ALTERNATE_OBJECT_DIRECTORIES',None)
        try:
            from swechat_mining_storage import install as install_mining_storage
            from agentlog_unified import miner as miner_module
            finish_storage=install_mining_storage(miner_module)
            try:
                m=mine_repository(str(acquisition_path),a.tip,initials,
                    max_commits=config['mining']['max_history_commits_per_repository'],max_source_bytes=config['mining']['max_source_file_bytes'])
            finally:
                storage_stats=finish_storage()
            if mirrored:restore_source_identity(m,p)
        finally:
            if prior_alternates is not None:os.environ['GIT_ALTERNATE_OBJECT_DIRECTORIES']=prior_alternates
            else:os.environ.pop('GIT_ALTERNATE_OBJECT_DIRECTORIES',None)
    m['platform_adapter']={'mining_platform':'linux','python_version':sys.version.split()[0],
        'pydriller_version':__import__('pydriller').__version__,'source_analysis_platform':'research_Windows_Python_after_guard',
        'native_object_mirror':mirrored,'frozen_graph_verified':mirrored,'logical_source_identity_preserved':True,
        'mirror_setup_failure_type':mirror_failure,'source_repository':str(p),'storage_adapter':storage_stats}
    dest=windows_path(a.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with gzip.open(dest,'wb',compresslevel=1) as f:pickle.dump(m,f,protocol=4)
    archive_hash=hashlib.sha256()
    with dest.open('rb') as f:
        for block in iter(lambda:f.read(8*1024*1024),b''):archive_hash.update(block)
    dump(dest.with_suffix('.receipt.json'),dict(status='complete_acquisition_checkpoint',repository=a.repository,
        target_tip=a.tip,initial_shas=initials,source_repository=str(p),compressed_sha256=archive_hash.hexdigest(),
        commits=len(m['commits']),file_changes=len(m['changes']),gaps=len(m['gaps']),
        raw_retention_policy='unchanged_delete_after_parent_load',source_content_in_receipt=False))
    print(json.dumps(dict(commits=len(m['commits']),files=len(m['changes']),gaps=len(m['gaps']))),flush=True)
