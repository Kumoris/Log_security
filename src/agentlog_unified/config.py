from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import subprocess
import sys
import yaml
from . import __version__
from .paths import project_path
from .storage import canonical, atomic_write

PROJECT = Path(__file__).resolve().parents[2]
STAGES = ['ingest', 'collect', 'mine', 'detect', 'trace', 'assess', 'export']


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def load_config(path: str, input_override: str | None = None) -> dict:
    defaults = yaml.safe_load((PROJECT / 'config.example.yaml').read_text())
    config = yaml.safe_load(Path(path).read_text()) or {}
    for key, value in config.items():
        if isinstance(value, dict) and isinstance(defaults.get(key), dict):
            defaults[key].update(value)
        else:
            defaults[key] = value
    config = defaults
    config['project_dir'] = str(PROJECT)
    if input_override:
        config['input']['prs_path'] = str(Path(input_override).resolve())
    for key in ('prs_path', 'repositories_path', 'provenance_path'):
        if config['input'].get(key):
            config['input'][key] = str(project_path(config['input'][key], PROJECT))
    config['mining']['repository_cache'] = str(project_path(config['mining']['repository_cache'], PROJECT))
    if config['run_mode'] not in {'smoke','pilot','full'}:
        raise ValueError('run_mode must be smoke, pilot or full')
    if config['mining']['engine'] != 'pydriller' or config['mining']['num_workers_per_repository'] != 1:
        raise ValueError('This implementation requires PyDriller and one worker per repository')
    if config['analysis']['privacy_filter_before_trace'] or config['mining'].get('followup_author_filter'):
        raise ValueError('Privacy/author prefilters are prohibited')
    if config['analysis']['llm_enabled'] or config['analysis']['execute_target_code'] or config['analysis']['external_paid_llm_calls']:
        raise ValueError('This package supports static, model-free execution only')
    if config['analysis']['dependency_depth'] != 1 or not config['storage']['export_redacted']:
        raise ValueError('Requires bounded depth 1 and redacted exports')
    if config['mining']['skip_file_globs'] or config['mining']['skip_whitespaces']:
        raise ValueError('Silent file and whitespace exclusion is unsupported')
    for key in ('max_history_commits_per_repository','max_source_file_bytes','max_snapshot_files','max_download_gb'):
        if config['mining'][key] <= 0:
            raise ValueError(f'{key} must be positive')
    if config['observation']['days'] <= 0:
        raise ValueError('observation days must be positive')
    return config


def sampling_limits(config: dict) -> tuple[int | None, int | None]:
    """Full means all input PRs/repositories; explicit Git budgets still apply."""
    if config['run_mode'] == 'full':
        return None, None
    mode = config['run_mode']
    return (config['sampling'][mode+'_max_initial_agent_prs'],
            config['sampling'][mode+'_max_repositories'])


def versions() -> dict:
    return {'program':__version__, 'python':sys.version.split()[0], 'git':subprocess.run(['git','--version'],capture_output=True,text=True,check=True).stdout.strip(), **{p:importlib.metadata.version(p) for p in ('PyDriller','GitPython','PyYAML','pytest','jsonschema')}}


def init_run(config: dict, run_id: str, resume: bool, argv: list[str]) -> tuple[Path, dict]:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}', run_id):
        raise ValueError('Invalid run ID')
    run = PROJECT/'outputs/runs' / run_id
    manifest_path = run / 'run_manifest.json'
    config_hash = hashlib.sha256(canonical(config).encode()).hexdigest()
    code_hash = hashlib.sha256(''.join(sha256_file(p) for p in sorted((PROJECT/'src').rglob('*.py'))).encode()).hexdigest()
    inputs = {k: {'path':v,'sha256':sha256_file(Path(v))} for k,v in config['input'].items() if k.endswith('_path') and v}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if manifest['config_hash'] != config_hash or manifest['input_versions'] != inputs or manifest.get('code_sha256') != code_hash:
            raise ValueError('Frozen run config/input/program changed; use a new run ID')
        manifest['commands'].append({'utc':now(),'argv':argv,'resume':resume})
    else:
        run.mkdir(parents=True, mode=0o700)
        code_hash = hashlib.sha256(''.join(sha256_file(p) for p in sorted((PROJECT/'src').rglob('*.py'))).encode()).hexdigest()
        manifest = {'run_id':run_id,'schema_version':'2.0','config_hash':config_hash,'config':config,'input_versions':inputs,'source_revision':config.get('source_revision') or inputs,'code_sha256':code_hash,'collection_cutoff_utc':config.get('collection_cutoff_utc') or now(),'versions':versions(),'commands':[{'utc':now(),'argv':argv,'resume':resume}],'history_coverage':[],'external_paid_llm_calls':0,'target_code_executed':False,'stages':{}}
    atomic_write(manifest_path, json.dumps(manifest,ensure_ascii=False,indent=2))
    resolved = {**config, 'collection_cutoff_utc':manifest['collection_cutoff_utc']}
    resolved['storage'] = {**config['storage'],'index_database':str(run/config['storage']['index_database'])}
    atomic_write(run/'config.resolved.yaml',yaml.safe_dump(resolved,allow_unicode=True,sort_keys=False))
    return run,manifest
