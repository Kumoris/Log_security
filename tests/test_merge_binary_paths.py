from agentlog_unified.git_support import diff_paths, merge_diff_fallback
from synthetic_histories import HEADER, commit, init


def test_binary_add_delete_do_not_reject_the_code_diff(tmp_path):
    repo = tmp_path / 'repo'
    init(repo)
    (repo / 'old.png').write_bytes(b'\0' + bytes(range(256)) * 3)
    before = commit(repo, {'app.py': HEADER + 'logger.info("before")\n'}, 'before')
    (repo / 'old.png').unlink()
    (repo / 'new.png').write_bytes(b'\xff\0' + b'new payload' * 100)
    after = commit(repo, {'app.py': HEADER + 'logger.info("after", user.email)\n'}, 'after', day=3)
    files = merge_diff_fallback(str(repo), before, after)
    assert {(m.old_path, m.new_path) for m in files} == diff_paths(str(repo), before, after)
    assert (None, 'new.png') in {(m.old_path, m.new_path) for m in files}
    assert ('old.png', None) in {(m.old_path, m.new_path) for m in files}
    assert 'user.email' in next(m for m in files if m.new_path == 'app.py').source_code
