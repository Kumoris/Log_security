"""Read-only reuse of an earlier frozen run's immutable Git extraction.

Extension reuses extraction only. Detection, identity matching, tracing and
assessment run again against the new complete selected graph.
"""
from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path
import re
import sqlite3

from .git_support import disable_implicit_fetch, is_ancestor, resolve_ref, run_git
from .storage import canonical


def load_previous_run(project: Path, run_id: str, current_manifest: dict,
                      config: dict | None = None) -> dict:
    """Load a compatible frozen manifest/SQLite without changing either file."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", run_id):
        raise ValueError("Invalid previous run ID")
    runs = (Path(project) / "outputs/runs").resolve()
    run = (runs / run_id).resolve()
    if run.parent != runs or run_id == current_manifest.get("run_id"):
        raise ValueError("Extension requires a distinct run inside the project runs directory")
    try:
        previous_manifest = json.loads((run / "run_manifest.json").read_text())
    except (OSError, ValueError) as exc:
        raise ValueError("Previous run manifest is unavailable or invalid") from exc
    for key in ("code_sha256", "schema_version", "config_hash", "input_versions"):
        if key not in current_manifest or key not in previous_manifest or previous_manifest[key] != current_manifest[key]:
            raise ValueError("Previous run is incompatible: " + key)
    for key in ("PyDriller", "GitPython", "python", "git"):
        if previous_manifest.get("versions", {}).get(key) != current_manifest.get("versions", {}).get(key):
            raise ValueError("Previous extraction dependency version changed: " + key)
    if config is not None and canonical(config) != canonical(current_manifest.get("config")):
        raise ValueError("Current config differs from the current frozen manifest")
    filename = previous_manifest.get("config", {}).get("storage", {}).get("index_database")
    if not filename:
        raise ValueError("Previous run lacks its index database path")
    database = (run / filename).resolve()
    if not database.is_relative_to(run) or not database.is_file():
        raise ValueError("Previous database must exist inside its frozen run")
    # An uncheckpointed WAL is not an immutable snapshot. Never checkpoint an old run.
    if Path(str(database) + "-wal").exists():
        raise ValueError("Previous database has an active WAL; close/checkpoint that run first")
    try:
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
            stage = db.execute("SELECT status FROM stages WHERE name='mine'").fetchone()
            if not stage or stage[0] not in {"complete", "partial"}:
                raise ValueError("Previous run has no completed mining checkpoint")
            def rows(kind):
                return [json.loads(row[0]) for row in db.execute(
                    "SELECT data FROM records WHERE kind=? ORDER BY id", (kind,))]
            repositories, mined = rows("repositories"), rows("mined")
    except sqlite3.Error as exc:
        raise ValueError("Previous mining index cannot be read") from exc
    if not repositories or not mined:
        raise ValueError("Previous run lacks repository/mining records")
    return {"run_id": run_id, "manifest": previous_manifest,
            "repositories": repositories, "mined": mined}


def validate_extension(repositories: list[dict], previous_data: dict) -> dict[str, dict]:
    """Return previous mining results keyed by current repository ID, or fail closed.

    Same inputs/rules are checked by load_previous_run. Here physical repository,
    original cohort anchors and first-parent ancestry must still match. A rewritten
    or different branch history is a fresh run, not an extension.
    """
    disable_implicit_fetch()
    old = {row["id"]: row for row in previous_data["repositories"]}
    current = {row["id"]: row for row in repositories}
    if (set(old) != set(current) or len(old) != len(previous_data["repositories"])
            or len(current) != len(repositories)):
        raise ValueError("Extension repository set changed or is ambiguous")
    mined = {row["repository_id"]: row for row in previous_data["mined"]}
    if len(mined) != len(previous_data["mined"]) or set(old) != set(mined):
        raise ValueError("Previous mining records do not match its repository set")
    reusable = {}
    for identity, repo in current.items():
        prior = old[identity]
        path = str(Path(repo["local_repo_path"]).resolve())
        if (path != str(Path(prior["local_repo_path"]).resolve())
                or repo["repository_id"] != prior["repository_id"]
                or repo["target_ref"] != prior["target_ref"]):
            raise ValueError("Extension repository identity, path or target branch changed")
        if set(repo.get("initial_shas", [])) != set(prior.get("initial_shas", [])):
            raise ValueError("Extension initial PR commit anchors changed")
        old_tip, new_tip = prior["frozen_target_tip"], repo["frozen_target_tip"]
        if resolve_ref(path, old_tip) != old_tip or resolve_ref(path, new_tip) != new_tip:
            raise ValueError("Extension frozen tip object is unavailable")
        chain = run_git(path, ["rev-list", "--first-parent", new_tip]).stdout.splitlines()
        if old_tip not in chain or not is_ancestor(path, old_tip, new_tip):
            raise ValueError("Extension history was rewritten or left its previous first-parent chain")
        previous = mined[identity]
        if previous.get("repo_path") != path or previous.get("history_scope", {}).get("frozen_tip") != old_tip:
            raise ValueError("Previous mining snapshot does not match its repository metadata")
        reusable[identity] = {**previous, "source_run_id": previous_data["run_id"]}
    return reusable
