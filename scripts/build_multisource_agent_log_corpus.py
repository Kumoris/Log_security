#!/usr/bin/env python3
"""Build one evidence-aware log-line corpus from GitHub, AIDev, and SWE-chat."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Iterator

import pyarrow.parquet as pq

from analyze_coding_agent_log_leakage import is_production_path
from analyze_devgpt_logs import is_executable_log_line
from analyze_swe_chat_multilingual_logs import is_log_line, is_source_file
from mine_agent_unique_log_features import FEATURE_ORDER, feature_hits


csv.field_size_limit(sys.maxsize)


FIELDS = (
    "dataset",
    "provenance",
    "dataset_provenance",
    "attribution_granularity",
    "provenance_evidence",
    "comparison_stratum",
    "comparison_role",
    "repo",
    "source_id",
    "pr_key",
    "commit",
    "checkpoint",
    "file",
    "line",
    "line_coordinate_type",
    "scope",
    "log_text",
    "log_text_status",
    "risk_features",
    "static_risk_candidate",
    "line_authorship_proof",
    "runtime_leak_claim",
    "evidence_boundary",
    "context_evidence",
    "lineage_status",
    "binding_id",
    "binding_status",
    "provenance_grade",
    "generation_stage",
    "analysis_eligibility",
    "base_sha",
    "head_sha",
    "patch_sha256",
    "evidence_chain_status",
)


def ordered_features(text: str) -> list[str]:
    hits = feature_hits(text)
    return [name for name in FEATURE_ORDER if name in hits]


def parse_added_logs(patch: str) -> Iterator[tuple[int, str]]:
    for patch_line, raw_line in enumerate((patch or "").splitlines(), start=1):
        if not raw_line.startswith("+") or raw_line.startswith("+++"):
            continue
        text = raw_line[1:].strip()
        if is_executable_log_line(text):
            yield patch_line, text


def github_rows(path: Path, bindings: dict[str, dict] | None = None) -> Iterator[dict[str, object]]:
    mapping = {
        "AGENT_SOURCE_CANDIDATE": "agent",
        "HUMAN_PR_SOURCE_CANDIDATE": "human",
    }
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            provenance = mapping.get(row.get("provenance", ""), "unknown")
            if provenance == "unknown":
                continue
            features = [value for value in row.get("risk_features", "").split(";") if value]
            binding = (bindings or {}).get(row.get("pr_key", ""), {}) if provenance == "agent" else {}
            grade = str(binding.get("provenance_grade") or row.get("provenance_grade") or "C")
            proof = bool(binding.get("line_authorship_proof")) and grade in {"A", "B"}
            eligibility = str((
                binding.get("analysis_eligibility")
                if provenance == "agent"
                else row.get("analysis_eligibility")
            ) or "sensitivity_only")
            if row.get("pair_analysis_eligibility") not in {None, "", "provenance_primary"}:
                eligibility = "sensitivity_only"
            yield {
                "dataset": "GitHub-matched-PR",
                "provenance": provenance,
                "dataset_provenance": row["provenance"],
                "attribution_granularity": "session_bound_pr_patch" if proof else "pr_level_candidate",
                "provenance_evidence": str(binding.get("hard_anchor") or row.get("provenance_evidence", "")),
                "comparison_stratum": "github_matched_pr",
                "comparison_role": "matched_agent_human_pr",
                "repo": row.get("repo", ""),
                "source_id": row.get("pr_key", ""),
                "pr_key": row.get("pr_key", ""),
                "commit": str(binding.get("pr_head_sha") or row.get("pr_head_sha") or ""),
                "checkpoint": "",
                "file": row.get("file", ""),
                "line": row.get("line", ""),
                "line_coordinate_type": "new_file_line",
                "scope": row.get("path_scope", ""),
                "log_text": row.get("log_text_redacted", ""),
                "log_text_status": "redacted",
                "risk_features": ";".join(features),
                "static_risk_candidate": str(bool(features)).lower(),
                "line_authorship_proof": str(proof).lower(),
                "runtime_leak_claim": "false",
                "evidence_boundary": (
                    "Session-to-PR hard anchor supports line attribution"
                    if proof else "PR-level source candidate; not line authorship proof"
                ),
                "context_evidence": "",
                "lineage_status": row.get("lineage_status", ""),
                "binding_id": binding.get("binding_id", ""),
                "binding_status": binding.get("binding_status", row.get("binding_status", "not_evaluated")),
                "provenance_grade": grade,
                "generation_stage": binding.get(
                    "generation_stage", row.get("generation_stage", "merged_final_unresolved_actor")
                ),
                "analysis_eligibility": eligibility,
                "base_sha": binding.get("pr_base_sha", row.get("base_sha", "")),
                "head_sha": binding.get("pr_head_sha", row.get("pr_head_sha", "")),
                "patch_sha256": binding.get("pr_patch_sha256", row.get("canonical_patch_sha256", "")),
                "evidence_chain_status": binding.get(
                    "github_evidence_chain_status", row.get("evidence_chain_status", "legacy_unhashed_snapshot")
                ),
            }


def swe_chat_rows(path: Path) -> Iterator[dict[str, object]]:
    mapping = {"agent_only": "agent", "human_only": "human", "mixed": "mixed"}
    seen: set[tuple[str, ...]] = set()
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            raw_provenance = row.get("attribution", "")
            text = row.get("log_text", "")
            if (
                row.get("add_remove") != "add"
                or raw_provenance not in mapping
                or not is_executable_log_line(text)
            ):
                continue
            key = tuple(row.get(name, "") for name in ("repo", "commit", "checkpoint_pk", "file", "line", "log_text"))
            if key in seen:
                continue
            seen.add(key)
            features = ordered_features(text)
            provenance = mapping[raw_provenance]
            yield {
                "dataset": "SWE-chat",
                "provenance": provenance,
                "dataset_provenance": raw_provenance,
                "attribution_granularity": "file_version_attribution",
                "provenance_evidence": "checkpoint_file_attribution",
                "comparison_stratum": "swe_chat_file_attribution",
                "comparison_role": "agent_human_comparison" if provenance != "mixed" else "mixed_sensitivity_only",
                "repo": row.get("repo", ""),
                "source_id": row.get("checkpoint_pk", ""),
                "pr_key": "",
                "commit": row.get("commit", ""),
                "checkpoint": row.get("checkpoint_pk", ""),
                "file": row.get("file", ""),
                "line": row.get("line", ""),
                "line_coordinate_type": "version_file_line",
                "scope": "production" if is_production_path(row.get("file", "")) else "non_production",
                "log_text": text,
                "log_text_status": "dataset_snapshot_may_be_redacted",
                "risk_features": ";".join(features),
                "static_risk_candidate": str(bool(features)).lower(),
                "line_authorship_proof": "false",
                "runtime_leak_claim": "false",
                "evidence_boundary": "File attribution inherited by log line; mixed is not a source label",
                "context_evidence": row.get("manual_review_evidence", ""),
                "lineage_status": row.get("manual_review_label", ""),
                "binding_id": "",
                "binding_status": "not_evaluated",
                "provenance_grade": "C",
                "generation_stage": "dataset_snapshot_unresolved_actor",
                "analysis_eligibility": "sensitivity_only",
                "base_sha": "",
                "head_sha": row.get("commit", ""),
                "patch_sha256": "",
                "evidence_chain_status": "checkpoint_file_attribution",
            }


def aidev_rows(directory: Path) -> Iterator[dict[str, object]]:
    metadata: dict[int, tuple[str, str]] = {}
    for batch in pq.ParquetFile(directory / "pull_request.parquet").iter_batches(
        columns=["id", "agent", "repo_url"], batch_size=50_000
    ):
        values = batch.to_pydict()
        for pr_id, agent, repo_url in zip(values["id"], values["agent"], values["repo_url"]):
            if pr_id is not None:
                metadata[int(pr_id)] = (
                    str(agent or "unknown"),
                    str(repo_url or "").removeprefix("https://api.github.com/repos/"),
                )

    seen: set[tuple[object, ...]] = set()
    patch_file = pq.ParquetFile(directory / "pr_commit_details.parquet")
    for batch in patch_file.iter_batches(columns=["pr_id", "sha", "filename", "patch"], batch_size=20_000):
        values = batch.to_pydict()
        for pr_id, sha, filename, patch in zip(
            values["pr_id"], values["sha"], values["filename"], values["patch"]
        ):
            if pr_id is None or int(pr_id) not in metadata or not isinstance(patch, str):
                continue
            file = str(filename or "")
            if not is_source_file(file):
                continue
            agent, repo = metadata[int(pr_id)]
            for patch_line, text in parse_added_logs(patch):
                key = (repo, str(sha or ""), file, patch_line, text)
                if key in seen:
                    continue
                seen.add(key)
                features = ordered_features(text)
                yield {
                    "dataset": "AIDev",
                    "provenance": "agent",
                    "dataset_provenance": agent,
                    "attribution_granularity": "agentic_pr_patch",
                    "provenance_evidence": "dataset_agentic_pr_and_commit_patch",
                    "comparison_stratum": "aidev_agentic_pr_patch",
                    "comparison_role": "agent_only_no_human_patch_control",
                    "repo": repo,
                    "source_id": f"aidev_pr:{int(pr_id)}",
                    "pr_key": f"aidev_pr:{int(pr_id)}",
                    "commit": str(sha or ""),
                    "checkpoint": "",
                    "file": file,
                    "line": patch_line,
                    "line_coordinate_type": "patch_line",
                    "scope": "production" if is_production_path(file) else "non_production",
                    "log_text": text,
                    "log_text_status": "dataset_patch",
                    "risk_features": ";".join(features),
                    "static_risk_candidate": str(bool(features)).lower(),
                    "line_authorship_proof": "false",
                    "runtime_leak_claim": "false",
                    "evidence_boundary": "Agentic PR patch inclusion; no patched human control and not line authorship gold",
                    "context_evidence": "",
                    "lineage_status": "",
                    "binding_id": "",
                    "binding_status": "not_evaluated",
                    "provenance_grade": "C",
                    "generation_stage": "agentic_pr_patch_unresolved_actor",
                    "analysis_eligibility": "sensitivity_only",
                    "base_sha": "",
                    "head_sha": str(sha or ""),
                    "patch_sha256": "",
                    "evidence_chain_status": "dataset_agentic_pr_commit_patch",
                }


def load_bindings(path: Path | None) -> dict[str, dict]:
    if path is None or not path.exists():
        return {}
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return {str(row.get("pr_key") or ""): row for row in rows if row.get("pr_key")}


def write_corpus(
    rows: Iterable[dict[str, object]], path: Path
) -> tuple[int, Counter, Counter, Counter, Counter, Counter, dict[str, dict[str, int]]]:
    total = 0
    by_dataset: Counter = Counter()
    by_provenance: Counter = Counter()
    by_scope: Counter = Counter()
    by_risk: Counter = Counter()
    by_evidence: Counter = Counter()
    repos: dict[str, set[str]] = defaultdict(set)
    source_units: dict[str, set[str]] = defaultdict(set)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
            total += 1
            by_dataset[str(row["dataset"])] += 1
            by_provenance[f'{row["dataset"]}:{row["provenance"]}'] += 1
            by_scope[f'{row["dataset"]}:{row["scope"]}'] += 1
            if row["static_risk_candidate"] == "true":
                by_risk[f'{row["dataset"]}:{row["provenance"]}'] += 1
            by_evidence[f'grade:{row["provenance_grade"]}'] += 1
            by_evidence[f'eligibility:{row["analysis_eligibility"]}'] += 1
            by_evidence["line_authorship_proven"] += row["line_authorship_proof"] == "true"
            repos[str(row["dataset"])].add(str(row["repo"]))
            source_units[str(row["dataset"])].add(str(row["source_id"]))
    diversity = {
        dataset: {
            "repositories": len(repos[dataset] - {""}),
            "source_units": len(source_units[dataset] - {""}),
        }
        for dataset in by_dataset
    }
    return total, by_dataset, by_provenance, by_scope, by_risk, by_evidence, diversity


def fingerprint(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "size_bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-lineage", type=Path, default=Path("outputs/github_log_lineage_poc/log_lineage.csv"))
    parser.add_argument(
        "--github-bindings", type=Path,
        default=Path("outputs/github_session_pr_binding/provenance_bindings.jsonl"),
    )
    parser.add_argument("--aidev-dir", type=Path, default=Path("data/repos/AIDev"))
    parser.add_argument(
        "--swe-candidates",
        type=Path,
        default=Path("data/res/swe_chat_multilingual_logs/swe_chat_multilingual_log_candidates.csv"),
    )
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/multisource_agent_log_corpus"))
    args = parser.parse_args()

    required = [
        args.github_lineage,
        args.aidev_dir / "pull_request.parquet",
        args.aidev_dir / "pr_commit_details.parquet",
        args.swe_candidates,
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        parser.error("missing required input(s): " + ", ".join(missing))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    corpus_path = args.output_dir / "log_rows.csv"
    bindings = load_bindings(args.github_bindings)
    rows = (
        row
        for source in (
            github_rows(args.github_lineage, bindings), aidev_rows(args.aidev_dir), swe_chat_rows(args.swe_candidates)
        )
        for row in source
    )
    total, by_dataset, by_provenance, by_scope, by_risk, by_evidence, diversity = write_corpus(rows, corpus_path)

    summary = {
        "total_log_rows": total,
        "by_dataset": dict(sorted(by_dataset.items())),
        "by_dataset_and_provenance": dict(sorted(by_provenance.items())),
        "by_dataset_and_scope": dict(sorted(by_scope.items())),
        "static_risk_candidates_by_dataset_and_provenance": dict(sorted(by_risk.items())),
        "distinct_repositories_and_source_units": dict(sorted(diversity.items())),
        "negative_control_log_rows": total - sum(by_risk.values()),
        "evidence_counts": dict(sorted(by_evidence.items())),
        "inputs": {
            "GitHub-matched-PR": fingerprint(args.github_lineage),
            "AIDev-pull-request": fingerprint(args.aidev_dir / "pull_request.parquet"),
            "AIDev-patches": fingerprint(args.aidev_dir / "pr_commit_details.parquet"),
            "SWE-chat-derived-log-lines": fingerprint(args.swe_candidates),
            **({"GitHub-session-bindings": fingerprint(args.github_bindings)} if args.github_bindings.exists() else {}),
        },
        "upstream_datasets": {
            "GitHub-matched-PR": "self-built public GitHub PR cohort",
            "AIDev": "hao-li/AIDev",
            "SWE-chat": "SALT-NLP/SWE-chat",
        },
        "comparison_rules": {
            "GitHub-matched-PR": "PR-level matched comparison; keep separate from line authorship",
            "AIDev": "Agent-only extraction because human PR rows have no linked patch control",
            "SWE-chat": "Compare agent_only and human_only within this dataset; report mixed separately",
            "cross_dataset_pooling": "not_allowed_without_harmonized sampling units and repository controls",
        },
        "boundaries": {
            "line_authorship_proof_for_all_rows": False,
            "line_authorship_proven_rows": by_evidence["line_authorship_proven"],
            "runtime_leak_claim": False,
            "static_risk_candidate_only": True,
        },
        "provenance_policy": {
            "merged_A_or_B_with_verified_human_same_repo": "provenance_primary",
            "open_A_or_B": "provenance_validation_only",
            "C_or_D": "sensitivity_only",
            "missing_binding_file": "legacy rows remain grade C and sensitivity-only",
        },
        "output": str(corpus_path),
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    with (args.output_dir / "source_counts.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["dataset", "provenance", "n_logs", "n_static_risk_candidates", "candidate_rate"])
        for key, count in sorted(by_provenance.items()):
            dataset, provenance = key.split(":", 1)
            candidates = by_risk[key]
            writer.writerow([dataset, provenance, count, candidates, f"{candidates / count:.6f}"])
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
