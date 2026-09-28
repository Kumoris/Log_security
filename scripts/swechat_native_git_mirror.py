"""An ephemeral, content-addressed Git object mirror for acquisition I/O only.

Sources stay unchanged. No checkout, hooks, source execution or network fetch.
The ordinary miner still selects and extracts the same frozen objects.
"""
from contextlib import contextmanager
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import hashlib
import inspect
import json


@contextmanager
def native_mirror(source, revisions, environment):
    source = Path(source)
    with tempfile.TemporaryDirectory(prefix='swechat-mining-objects-', dir='/tmp') as temporary:
        root = Path(temporary)
        target = root / 'repository.git'
        # This helper is for the newly collected bare repositories only.
        if not (source / 'HEAD').is_file() or (source / '.git').exists():
            raise ValueError('Expected a collected bare Git repository')
        shutil.copytree(source, target)
        def git(path, args, env):
            command = ['git', '--no-pager', '-c', 'core.hooksPath=' + str(root / 'no-hooks'),
                       '-c', 'core.fsmonitor=false', '-c', 'gc.auto=0', '-C', str(path), *args]
            return subprocess.run(command, env=env, capture_output=True, check=True).stdout
        source_env = environment(source)
        available = []
        for revision in revisions:
            resolved = subprocess.run(['git', '-C', str(source), 'rev-parse', '--verify', revision + '^{commit}'],
                                      env=source_env, capture_output=True)
            if resolved.returncode == 0:
                sha=resolved.stdout.decode().strip()
                git(target, ['update-ref', 'refs/swechat-mirror-frozen/' + str(len(available)), sha], source_env)
                available.append(sha)
        if not available:
            raise ValueError('No frozen commit could be resolved')
        # Repack locally so no data reads depend on NTFS alternates afterward.
        git(target, ['-c', 'pack.compression=0', '-c', 'pack.window=0', 'repack', '-a', '-d'], source_env)
        alternate = target / 'objects/info/alternates'
        if alternate.exists():
            alternate.unlink()  # Only the newly created temporary mirror.
        standalone = dict(source_env)
        standalone.pop('GIT_ALTERNATE_OBJECT_DIRECTORIES', None)
        expected = git(source, ['rev-list', '--topo-order', '--reverse', '--parents', *available], source_env)
        actual = git(target, ['rev-list', '--topo-order', '--reverse', '--parents', *available], standalone)
        if expected != actual:
            raise ValueError('Temporary Git mirror changed the frozen commit graph')
        git(target, ['fsck', '--connectivity-only', '--no-dangling', *available], standalone)
        yield target, standalone


def restore_source_identity(mined, source):
    """Keep the unchanged miner's path-based row IDs tied to the logical source."""
    from agentlog_unified.miner import _record_file
    if 'identity = json.dumps(["2.0", str(Path(repo_path).resolve()), parent, sha,' not in inspect.getsource(_record_file):
        raise RuntimeError('Original miner identity formula changed')
    original_path=str(Path(source).resolve())
    for row in mined['changes']:
        identity=json.dumps(['2.0',original_path,row['parent_sha'],row['sha'],row['old_path'],row['new_path']],ensure_ascii=False)
        row['change_id']=hashlib.sha256(identity.encode()).hexdigest()[:24]
    mined['repo_path']=original_path
    return mined
