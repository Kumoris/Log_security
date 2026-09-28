"""Synthetic Git oracle: branches and exact mined sources survive the I/O mirror."""
import json
import os
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from swechat_native_git_mirror import native_mirror, restore_source_identity
from run_swechat_followups import environment
from agentlog_unified.miner import mine_repository, _file_fingerprint


def git(path, *args):
    return subprocess.run(['git', '-C', str(path), *args], check=True, capture_output=True).stdout.decode().strip()


def test_mirror_keeps_unreferenced_initial_and_exact_sources(tmp_path):
    work = tmp_path / 'work'; work.mkdir()
    git(work, 'init', '-b', 'main')
    git(work, 'config', 'user.name', 'Synthetic fixture')
    git(work, 'config', 'user.email', 'fixture@example.invalid')
    (work / 'fixture.py').write_text("print('fixture one')\n")
    git(work, 'add', '.'); git(work, 'commit', '-m', 'synthetic initial')
    initial = git(work, 'rev-parse', 'HEAD')
    git(work, 'checkout', '-b', 'side')
    (work / 'fixture.py').write_text("print('fixture side')\n")
    git(work, 'commit', '-am', 'synthetic off-target object')
    off_target = git(work, 'rev-parse', 'HEAD')
    git(work, 'checkout', 'main')
    (work / 'fixture.py').write_text("print('fixture two')\n")
    git(work, 'commit', '-am', 'synthetic target modification')
    target = git(work, 'rev-parse', 'HEAD')
    bare = tmp_path / 'source.git'
    subprocess.run(['git', 'clone', '--bare', '--shared', str(work), str(bare)], check=True, capture_output=True)
    git(bare, 'update-ref', '-d', 'refs/heads/side')
    os.environ.update(environment(bare))
    original = mine_repository(str(bare), target, [initial, off_target])
    before_refs = git(bare, 'show-ref')
    with native_mirror(bare, [target, initial, off_target], environment) as (mirror, env):
        previous = os.environ.get('GIT_ALTERNATE_OBJECT_DIRECTORIES')
        os.environ.pop('GIT_ALTERNATE_OBJECT_DIRECTORIES', None)
        try:
            copied = mine_repository(str(mirror), target, [initial, off_target])
            restore_source_identity(copied, bare)
        finally:
            if previous is not None:
                os.environ['GIT_ALTERNATE_OBJECT_DIRECTORIES'] = previous
        assert original['changes'] == copied['changes']
        assert original['repo_path'] == copied['repo_path']
        assert original['graph'] == copied['graph']
        assert original['selected_shas'] == copied['selected_shas']
        assert original['first_parent_shas'] == copied['first_parent_shas']
        assert original['commits'] == copied['commits']
        assert _file_fingerprint(original['changes']) == _file_fingerprint(copied['changes'])
        assert original['gaps'] == copied['gaps'] == []
        assert git(mirror, 'rev-parse', off_target) == off_target
    assert not mirror.exists()
    assert git(bare, 'show-ref') == before_refs
