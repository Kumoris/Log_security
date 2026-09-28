"""The collector must spend its import budget like the offline miner."""
import json

from agentlog_unified import object_acquisition as acquire
from agentlog_unified.batch_mine import run_batch
from synthetic_histories import HEADER, commit, init
from test_object_acquisition import remote_transport, seed


def test_import_budget_stops_after_each_first_existing_candidate(tmp_path, monkeypatch):
    repo = tmp_path / "remote"
    init(repo)
    helpers = {
        f"h{i}.py": f"# distinct helper {i}\ndef value(user):\n    return user.password\n"
        for i in range(12)
    }
    commit(repo, {**helpers, "pkg/app.py": HEADER + 'logger.info("fixed")\n'}, "before")
    sha = commit(repo, {"pkg/app.py": HEADER
        + "".join(f"import h{i}\n" for i in range(12))
        + "def run(user):\n"
        + "".join(f'    logger.info("v", h{i}.value(user))\n' for i in range(12))}, "after", day=3)
    requests = remote_transport(monkeypatch, repo)
    batch = seed(tmp_path, sha)
    collection = acquire.collect_batch_objects(batch, tmp_path / "cache", offline=False)
    assert collection["this_run_status_counts"] == {"objects_ready_for_offline_mining": 1}
    acquisition_calls = len(requests)
    mined = run_batch(batch, tmp_path / "cache", offline=True, max_dependency_files=40)
    assert mined["actual_extraction_metrics"]["pydriller_commits"] == 1
    assert mined["actual_extraction_metrics"]["dependency_blobs_read"] == 12
    assert mined["commit_status_counts"] == {"complete": 1}
    assert len(requests) == acquisition_calls
    acquisitions = [json.loads(line) for line in
                    (batch / "collection/object_acquisitions.jsonl").read_text().splitlines()]
    assert acquisitions[0]["metrics"]["direct_import_blobs_objects_missing_before"] == 12
