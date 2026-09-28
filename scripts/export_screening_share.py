#!/usr/bin/env python3
"""Create a separate, metadata-only share copy without changing frozen analysis.

This standard-library exporter never imports target/framework source, changes
src/config, calls a network service, or copies raw graphs/source. Original review
materials remain private. Unknown text and source-derived names become SHA256
references with a separate 0600 local mapping outside the share package.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import tempfile

VERSION = "screening-share-metadata-v1"
REF = re.compile(r"^(?:text|path|repository|field|artifact)_sha256:[0-9a-f]{64}$")
HEX = re.compile(r"^[0-9a-f]{24}(?:[0-9a-f]{16}|[0-9a-f]{40})?$")
UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
HASH_FIELDS = {"sha", "source_sha", "event_sha", "parent_sha", "commit_sha", "old_source_sha", "new_source_sha"}
NAME_FIELDS = {"field", "output_key", "name", "function_scope", "symbol"}
DROP = {"code_view", "source", "source_code", "source_code_before", "statement", "snippet", "text", "files",
        "repo_path", "source_path", "snapshot_ref", "local_source_ref", "private_source_index", "raw", "raw_source",
        "source_backends", "legacy_metrics", "actual_code_sha256", "workspace_status", "uncommitted_patch"}
BLIND_DROP = {"queue", "queue_label", "queue_reason", "variant", "assessment", "dimensions", "base_evidence",
              "attribution", "source_sensitivity", "output_sensitivity", "risk_clues", "rule_result", "ai_review", "human_review"}
ENUMS = set("A B C D baseline dfg_augmented before after supported suspected not_found unknown partial not_established not_applicable raw partial_mask transformed fixed call_argument log_record formatted_output success succeeded processed complete completed pending submitted blocked excluded started interrupted pending_adjudication adjudicated human ai adjudication reviewer_1 reviewer_2 evaluation engineering full_census_batch test example generated_or_vendor development_tool application_or_unknown low medium high critical supported_static supported_within_scope incomplete structural_ast possible metadata assignment reaching_definition actual_to_formal return_value call_return field_read parameter_use write projection log_argument function_parameter constant unknown_boundary budget_boundary not_assessed privacy_not_assessed null python javascript typescript go java csharp Python JavaScript TypeScript Go Java CSharp C# js ts py mixed literal formal_parameter trace_boundary parameter definition expression control_condition serialization composite unresolved pending_human_evaluation pending_file_level_human_audit evaluated_declared_sample evaluated_declared_file_sample static_risk_evidence_supported suspected_risk_needs_evidence no_risk_found_within_checked_scope unable_to_determine materialized_not_analyzed absent_verified object_unavailable extraction_failed stdout_argument stdout_separator message_template format_argument structured_extra structured_extra_field structured_field structured_field_field object_remainder_unknown implicit_exception unresolved_keyword_expansion policy_version_not_available original_modified_file not_evaluated value derived not_verified self_declared_not_authenticated executed".split())
STATE_FIELDS = set("queue baseline_queue dfg_queue before_queue after_queue status processing_status baseline_status dfg_status kind origin annotator_slot split side language scope level source_sensitivity output_sensitivity connection processing boundary certainty source_state old_source_state new_source_state variant role output_role endpoint sensitivity mapping_status identity_verification review_scope".split())
KEYS = set("case_id analysis_id attempt_id log_id original_log_id evidence_id path_id file_version_id commit_id group_id id repository repository_id sha source_sha event_sha parent_sha commit_sha source_sha256 source_hash source_versions source_state old_source_state new_source_state snapshot_sha256 path field output_key function_scope symbol name log_anchor output_anchor source_anchor old_anchor new_anchor old_output_anchor new_output_anchor anchor line end_line column end_column start_byte end_byte node_kind parser output_sha256 log_statement_sha256 split_version scope language side output_role output_index boundary api policy_version policy_sha256 rule_version prompt_template_version evidence_sha256 evidence_ids evidence_index evidence artifact_hashes queue queue_label queue_reason runtime_confirmed runtime_verified human_confirmed processing_status failure_reason assessment dimensions source_sensitivity output_sensitivity connection reason_code processing kind steps paths risk_clues critical_unknowns noncritical_unknowns checks_complete non_sensitive_basis limitations severity level reason certainty status executed result ai_review human_review review_status rule_result facts inferences text_sha256 rationale_sha256 critical_unknown_count reviewer_hash identity_verification raw_record_sha256 recorded_at origin reviewer annotator_slot timestamp annotation_ids metadata actual_source_sha256 model_id_sha256 raw_metadata_location input_sha256 output_sha256 input_hashes output_hashes split case_hashes machine_answers_included raw_source_included review_requirement started_at finished_at elapsed_seconds cpu_seconds max_rss_platform_units cache_hit base_evidence_origin timing_scope dfg_reason_codes base_evidence_sha256 base_sha256 code_signature source_locations business_source_confirmed role connection_supported semantics_supported semantics_status edge_ids source_anchor origin_category graph_id value_edges effective_propagation_edges origin_counts gaps history_locations_valid primary_cases expected_analyses actual_analyses missing unexpected duplicate_results paired_base_evidence_equal queue_migrations variants graphs graphs_with_structural_value_edges graph_evidence attempts interrupted_attempts batch_states languages scope_counts human_labels ai_reviews precision recall accuracy f1 metrics_reason acceptance process_integrity real_DFG_applicability synthetic_semantics claims_excluded count queue_counts processing_status_counts critical_unknown_cases critical_unknown_ratio batch_id baseline_analysis_id dfg_analysis_id baseline_queue dfg_queue baseline_status dfg_status base_evidence_equal baseline_seconds dfg_seconds comparison_version pair_id counterpart_case_id candidate_counterpart_ids pairing_status pairing_basis uncertainty old_source_sha new_source_sha comparison_strategy variant_changes change_label unselected_counterpart_analysis_inferred attribution_inferred_from_risk_change attribution commit_association granularity output_unit_authorship agent_introduction risk_judgment log_detection human_gold_count ai_used_as_gold declared_cases binary_gold_cases positive_definition population_accuracy_claim declared_file_count binary_audited_file_count output_units_are_not_detection_denominator tp fp fn tn precision_denominator recall_denominator input_records input_records_mapped commits commit_states file_versions file_states source_states file_languages file_scopes reason_counts log_versions output_units source_input_hashes duplicates case_file_mapping_valid case_file_source_hash_mismatches full_source_discovery_completed full_DFG_analyzed population_risk_rate denominators covered_files changed_files frame_coverage population_prevalence_claim full_output_frame primary_selected evaluation_selected full_batch_count batch_limit groups holdout_groups engineering_frame evaluation_frame seed quotas evaluation_quotas stratum stratum_information_time group_rule replacement_policy ai_or_human_in_primary_AB created_at config_sha256 population_sha256 frame_sha256 selection_sha256 evaluation_sha256 groups_sha256 batches_sha256 full_batches_sha256 frame_artifact log_anchors inspection_complete critical_unknowns review_scope blank provenance source_content_sha256 evidence_content_sha256 omitted_field_count artifact_ref source_artifact_ref format included source_sha256_for_artifact log_version_count source_index source_version_hashes processing_steps connection_reason source_frontier type_relationships evidence_ref".split())
COUNTER_KEYS = ENUMS | {a + "->" + b for a in "ABCD" for b in "ABCD"}
KEYS |= {"identity", "sha256", "snippet_sha256", "source_artifact_ref", "source_sha256_for_artifact", "format", "included"}
ENUMS |= {"json", "svg"}
STATE_FIELDS.add("format")
PUBLIC_FILES = {"cases.jsonl", "selection_manifest.json", "results.jsonl", "ab_pairs.jsonl", "paths.jsonl",
                "evidence_index.jsonl", "risk_labels.jsonl", "before_after.jsonl", "coverage.json", "attempts.jsonl",
                "ledger_coverage.json", "review/metrics.json", "review/review_manifest.json", "graph_inventory.jsonl", "README.md"}
PUBLIC_FILES |= {f"review/{slot}/{name}" for slot in ("reviewer_1", "reviewer_2") for name in ("blind_cases.jsonl", "annotations.jsonl")}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def hash_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as stream:
        stream.write(data)
    os.chmod(path, 0o600)


class Sanitizer:
    def __init__(self):
        self.mapping = {}

    def reference(self, value, category="text"):
        # Hash canonical type + content, keeping mappings stable across files.
        ref = category + "_sha256:" + digest_bytes(canonical(value).encode())
        self.mapping[ref] = {"category": category, "value": value}
        return ref

    def clean(self, value, key="", blind=False):
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("non_finite_source_metadata")
            return value
        if isinstance(value, str):
            if key.endswith("_ref") and REF.fullmatch(value):
                return value
            if key == "path" or key.endswith("_path"):
                return self.reference(value, "path")
            if key in {"repository", "repository_id"}:
                return self.reference(value, "repository")
            if key in NAME_FIELDS:
                return self.reference(value, "field")
            if key.endswith("_sha256") or key in HASH_FIELDS or key.endswith("_id") or key in {"id", "evidence_ids", "edge_ids", "annotation_ids", "candidate_counterpart_ids"}:
                if HEX.fullmatch(value) or UUID.fullmatch(value):
                    return value
            if key in STATE_FIELDS and value in ENUMS:
                return value
            return self.reference(value)
        if isinstance(value, list):
            return [self.clean(item, key, blind) for item in value]
        if isinstance(value, dict):
            if key == "artifact_hashes":
                return [{"artifact_ref": self.reference(k, "artifact"), "source_sha256_for_artifact": self.clean(v, "source_sha256")} for k, v in sorted(value.items())]
            result, omitted = {}, 0
            for child_key, child in value.items():
                if child_key in DROP or blind and child_key in BLIND_DROP:
                    omitted += 1
                    continue
                if key == "case_hashes" and HEX.fullmatch(child_key):
                    result[child_key] = self.clean(child, "source_sha256", blind)
                elif child_key in KEYS or child_key in COUNTER_KEYS:
                    result[child_key] = self.clean(child, child_key, blind)
                else:
                    omitted += 1
            if omitted:
                result["omitted_field_count"] = omitted
            return result
        raise ValueError("unsupported_source_metadata_type")


def _safe_leaf(value):
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float) and math.isfinite(value):
        return
    if isinstance(value, str) and (value in ENUMS or REF.fullmatch(value) or HEX.fullmatch(value) or UUID.fullmatch(value)):
        return
    raise ValueError("share_contains_unapproved_text")


def validate_public(value, blind=False, key=""):
    if isinstance(value, dict):
        for child_key, child in value.items():
            if child_key in DROP or blind and child_key in BLIND_DROP:
                raise ValueError("share_contains_private_or_prediction_field")
            if child_key not in KEYS and child_key not in COUNTER_KEYS and not (key == "case_hashes" and HEX.fullmatch(child_key)):
                raise ValueError("share_contains_unapproved_key")
            validate_public(child, blind, child_key)
    elif isinstance(value, list):
        for child in value:
            validate_public(child, blind, key)
    else:
        _safe_leaf(value)


README = """# 可分享元数据副本\n\n本目录是独立导出的元数据报告。原运行、原始复核包、源码、源码派生文本和真实 DFG 图均留在受限本地目录，不能将原运行整体公开。\n\n本包不复制任何原始图/SVG，图清单只保留案例、分析和原产物哈希。字段名、参数键、仓库、路径和未知文字统一替换为稳定 SHA256 引用；行列和内容哈希支持结合本地私有映射回查。分享副本不是完整代码证据，不能单凭它完成来源语义或人工真值确认。\n\nreviewer_1/reviewer_2 中盲包不含机器预测；各自独立标注仍需有权限读取原历史证据。原记录 evidence_sha256 被保留，包内 metadata-only 文件另有自身哈希。标注者应通过受限原包完成提交，不修改分享副本冒充原包。\n\n本包不会上传数据、不调用模型、不执行被审查项目，也不改变冻结分析结果或代码签名。运行 scripts/export_screening_share.py --verify --output 本目录 可重新校验白名单文本/字段及产物哈希。\n"""


def tighten_private_review(run):
    os.chmod(run, 0o700)
    review = run / "review"
    if not review.exists():
        return
    for path in [review, *review.rglob("*")]:
        if path.is_symlink():
            raise ValueError("private_review_symlink_refused")
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def build_package(run, label="main"):
    run = Path(run).resolve()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", label):
        raise ValueError("invalid_analysis_label")
    analysis = Path("analyses") / label
    sources = {
        "cases.jsonl": Path("selection/engineering.jsonl"),
        "selection_manifest.json": Path("selection/manifest.json"),
        "results.jsonl": analysis / "results.jsonl", "ab_pairs.jsonl": analysis / "ab_pairs.jsonl",
        "paths.jsonl": analysis / "paths.jsonl", "evidence_index.jsonl": analysis / "evidence_index.jsonl",
        "risk_labels.jsonl": analysis / "risk_labels.jsonl", "before_after.jsonl": analysis / "before_after.jsonl",
        "coverage.json": analysis / "coverage.json", "attempts.jsonl": analysis / "attempts.jsonl",
        "ledger_coverage.json": Path("coverage/ledger_coverage.json"),
        "review/metrics.json": Path("review/metrics.json"),
        "review/review_manifest.json": Path("review/review_manifest.json"),
    }
    for slot in ("reviewer_1", "reviewer_2"):
        for name in ("blind_cases.jsonl", "annotations.jsonl"):
            sources[f"review/{slot}/{name}"] = Path("review") / slot / name
    required = {"cases.jsonl", "selection_manifest.json", "results.jsonl", "coverage.json", "review/metrics.json",
                "review/reviewer_1/blind_cases.jsonl", "review/reviewer_2/blind_cases.jsonl"}
    clean, source_hashes, sanitizer, graph_inventory = {}, {}, Sanitizer(), []
    for target, relative in sources.items():
        path = run / relative
        if path.is_symlink() or not path.resolve().is_relative_to(run):
            raise ValueError("source_symlink_refused")
        if not path.is_file():
            if target in required:
                raise ValueError("analysis_or_review_export_not_ready")
            continue
        raw = path.read_bytes()
        source_hashes[str(relative)] = digest_bytes(raw)
        is_jsonl, blind = target.endswith(".jsonl"), "blind_cases" in target
        value = [json.loads(line) for line in raw.decode().splitlines() if line.strip()] if is_jsonl else json.loads(raw)
        if target == "results.jsonl":
            for row in value:
                for original, expected in row.get("artifact_hashes", {}).items():
                    rel = Path(original)
                    if rel.is_absolute() or ".." in rel.parts:
                        raise ValueError("unsafe_original_artifact_path")
                    artifact = run / analysis / rel
                    if artifact.is_symlink() or not artifact.resolve().is_relative_to(run) or not artifact.is_file() or hash_file(artifact) != expected:
                        raise ValueError("original_artifact_hash_mismatch")
                    source_hashes[str(analysis / rel)] = expected
                    if rel.parts and rel.parts[0] == "graphs":
                        graph_inventory.append(sanitizer.clean({"case_id": row.get("case_id"), "analysis_id": row.get("analysis_id"),
                            "attempt_id": row.get("attempt_id"), "source_sha256_for_artifact": expected,
                            "source_artifact_ref": sanitizer.reference(str(analysis / rel), "artifact"), "format": rel.suffix.lstrip("."), "included": False}))
        public = sanitizer.clean(value, blind=blind)
        validate_public(public, blind)
        text = "".join(canonical(row) + "\n" for row in public) if is_jsonl else canonical(public) + "\n"
        clean[target] = text.encode()
    validate_public(graph_inventory)
    clean["graph_inventory.jsonl"] = "".join(canonical(r) + "\n" for r in graph_inventory).encode()
    clean["README.md"] = README.encode()
    # Any metadata/source artifact modified during creation invalidates this pass.
    for relative, expected in source_hashes.items():
        if hash_file(run / relative) != expected:
            raise ValueError("original_artifact_changed_during_share_export")
    source_digest = digest_bytes(canonical(source_hashes).encode())
    mapping = {"version": VERSION, "source_set_sha256": source_digest,
               "source_artifacts": source_hashes, "references": sanitizer.mapping}
    manifest = {"version": VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
                "source_set_sha256": source_digest, "private_mapping_sha256": digest_bytes(canonical(mapping).encode()),
                "metadata_only": True, "raw_graphs_included": False, "original_review_is_private": True,
                "artifacts": {p: {"sha256": digest_bytes(data), "bytes": len(data)} for p, data in sorted(clean.items())}}
    return clean, manifest, mapping


def verify_package(output):
    output = Path(output).resolve()
    manifest = json.loads((output / "share_manifest.json").read_text())
    if set(manifest) != {"version", "created_at", "source_set_sha256", "private_mapping_sha256", "metadata_only", "raw_graphs_included", "original_review_is_private", "artifacts"}:
        raise ValueError("invalid_share_manifest_fields")
    try:
        timestamp = datetime.fromisoformat(manifest["created_at"])
        if timestamp.tzinfo is None or timestamp.isoformat() != manifest["created_at"]:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("invalid_share_timestamp") from None
    if manifest.get("version") != VERSION or manifest.get("metadata_only") is not True or manifest.get("raw_graphs_included") is not False:
        raise ValueError("invalid_share_manifest")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest.get("source_set_sha256", "")) or not re.fullmatch(r"[0-9a-f]{64}", manifest.get("private_mapping_sha256", "")):
        raise ValueError("invalid_share_manifest_hash")
    expected = set(manifest["artifacts"]) | {"share_manifest.json"}
    if set(manifest["artifacts"]) - PUBLIC_FILES or manifest.get("original_review_is_private") is not True:
        raise ValueError("unapproved_share_artifact")
    actual = {str(p.relative_to(output)) for p in output.rglob("*") if p.is_file()}
    if actual != expected or any(p.is_symlink() for p in output.rglob("*")):
        raise ValueError("share_file_set_mismatch")
    for relative, spec in manifest["artifacts"].items():
        if set(spec) != {"sha256", "bytes"} or not re.fullmatch(r"[0-9a-f]{64}", spec.get("sha256", "")) or type(spec.get("bytes")) is not int:
            raise ValueError("invalid_share_artifact_specification")
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("unsafe_share_artifact_path")
        data = (output / relative).read_bytes()
        if digest_bytes(data) != spec["sha256"] or len(data) != spec["bytes"]:
            raise ValueError("share_artifact_hash_mismatch")
        if relative == "README.md":
            if data != README.encode():
                raise ValueError("share_readme_mismatch")
            continue
        if relative.endswith(".jsonl"):
            for line in data.decode().splitlines():
                if line.strip():
                    validate_public(json.loads(line), "blind_cases" in relative)
        elif relative.endswith(".json"):
            validate_public(json.loads(data), "blind_cases" in relative)
        else:
            raise ValueError("unapproved_share_file_format")
    return {"status": "verified", "artifacts": len(manifest["artifacts"]), "metadata_only": True,
            "raw_graphs_included": False, "source_set_sha256": manifest["source_set_sha256"]}


def export_share(run, output=None, label="main", dry_run=False):
    run = Path(run).resolve()
    output = Path(output).resolve() if output else run / "share-report"
    if output == run or output in run.parents:
        raise ValueError("share_output_must_be_separate")
    clean, manifest, mapping = build_package(run, label)
    if dry_run:
        return {"status": "dry_run_validated", "artifacts": len(clean), "metadata_only": True,
                "source_set_sha256": manifest["source_set_sha256"], "source_or_output_written": False}
    if output.exists():
        raise ValueError("share_output_exists_choose_new_directory")
    tighten_private_review(run)
    mapping_dir = run / "private/share-maps"
    mapping_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(mapping_dir, 0o700)
    mapping_path = mapping_dir / (manifest["source_set_sha256"] + ".json")
    mapping_bytes = canonical(mapping).encode()
    if mapping_path.exists():
        if mapping_path.is_symlink() or mapping_path.read_bytes() != mapping_bytes:
            raise ValueError("private_share_mapping_conflict")
        os.chmod(mapping_path, 0o600)
    else:
        _write(mapping_path, mapping_bytes)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = Path(tempfile.mkdtemp(prefix=".screening-share-", dir=output.parent))
    try:
        for relative, data in clean.items():
            _write(temporary / relative, data)
        _write(temporary / "share_manifest.json", (canonical(manifest) + "\n").encode())
        verify_package(temporary)
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return verify_package(output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run")
    parser.add_argument("--output")
    parser.add_argument("--label", default="main")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.verify:
            if not args.output or args.dry_run:
                raise ValueError("verify_requires_output_without_dry_run")
            result = verify_package(args.output)
        else:
            if not args.run:
                raise ValueError("run_required")
            result = export_share(args.run, args.output, args.label, args.dry_run)
        print(canonical(result))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        code = str(exc) if isinstance(exc, ValueError) and re.fullmatch(r"[a-z_]+", str(exc)) else "share_export_validation_failed"
        print(canonical({"status": "blocked", "reason": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
