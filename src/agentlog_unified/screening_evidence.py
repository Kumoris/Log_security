"""Output-unit and frozen-history adapter for the existing detector and DFG.

No application code is imported/executed. All strings/literals in reportable
evidence are withheld; source hashes and exact anchors support local review.
This module supplies evidence, never final risk queues.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import re
import time
from pathlib import PurePosixPath

from .detector import PythonSnapshot, detect_snapshot, LANGUAGES, SENSITIVE, _name, _snippet, _types, MASKED
from .semantic_context import HistoricalContext, identifier
from .semantic_dfg import build_graph
from .semantic_evidence import digest, loc
from .semantic_ast import Syntax, CALLS
from .storage import stable_id

VERSION = "screening-output-split-1"
SHA = re.compile(r"[0-9a-f]{40}\Z")
CONTROLS = {"exc_info", "stack_info", "stacklevel"}


def _safe_name(value):
    return value if identifier(str(value)) else "field_" + digest(str(value))[:12]


def _versions(files, sha):
    return [{"path": p, "sha": sha, "source_sha256": digest(s)} for p, s in sorted(files.items())]


def _empty(boundary, reason="output_value_semantics_unresolved"):
    return {"evidence_ids": [], "source_sensitivity": "unknown", "output_sensitivity": "unknown",
            "connection": {"status": "not_established", "reason_code": "insufficient_evidence"},
            "processing": {"kind": "unknown", "steps": []}, "paths": [],
            "critical_unknowns": [reason], "noncritical_unknowns": ["runtime_output_unverified"],
            "boundary": deepcopy(boundary), "checks_complete": False, "non_sensitive_basis": [],
            "processing_status": "partial", "categories": []}


def _expression(node, boundary, field="", *, python=True):
    """Local output-only evidence; no name lookup or fabricated upstream chain."""
    result = _empty(boundary)
    kinds = set(_types(field)) & SENSITIVE
    if python:
        for child in ast.walk(node):
            if isinstance(child, ast.Name): kinds |= _types(child.id) & SENSITIVE
            elif isinstance(child, ast.Attribute): kinds |= _types(child.attr) & SENSITIVE
            elif isinstance(child, ast.Subscript) and isinstance(child.slice, ast.Constant) and isinstance(child.slice.value, str):
                kinds |= _types(child.slice.value) & SENSITIVE
        constants = [n.value for n in ast.walk(node) if isinstance(n, ast.Constant)]
        scalar = isinstance(node, ast.Constant)
    else:
        # node is a Syntax/text pair; only structural names and exact string
        # tokens are read. We do not run another lexical value-flow analyzer.
        syntax, item = node
        constants = []
        for child in syntax.nodes:
            if item.start_byte <= child.start_byte and child.end_byte <= item.end_byte:
                if child.type in {"identifier", "property_identifier", "field_identifier"}:
                    kinds |= _types(syntax.text(child)) & SENSITIVE
        scalar = item.type in {"string", "string_literal", "interpreted_string_literal", "raw_string_literal", "true", "false", "null", "nil", "integer", "int_literal", "number"}
        if scalar:
            raw = syntax.text(item)
            constants = [raw[1:-1] if len(raw) > 1 and raw[0] in "\"'`" else raw]
    literal_credentials = any(isinstance(v, str) and any(
        not MASKED.fullmatch(m.group(2)) and not m.group(2).startswith(("%", "{", "<"))
        for m in re.finditer(r"(?i)\b(password|passwd|secret|api_key|access_token|authorization)\s*[:=]\s*([^\s,;]+)", v)) for v in constants)
    safe_scalar = scalar and python and isinstance(node, ast.Constant) and (
        node.value is None or isinstance(node.value, bool) or
        isinstance(node.value, str) and (bool(MASKED.fullmatch(node.value)) or node.value in {"ok", "done", "started", "finished"}))
    result["categories"] = sorted(kinds | ({"credential"} if literal_credentials else set()))
    if literal_credentials:
        result.update(source_sensitivity="supported", output_sensitivity="supported", critical_unknowns=[], processing_status="success")
        result["connection"] = {"status": "supported", "reason_code": "literal_zero_hop"}
        result["processing"] = {"kind": "fixed" if scalar else "transformed", "steps": ["literal_credential_assignment_at_output"]}
        # A nested literal consumed by an arbitrary function is not itself the
        # output. A real DFG is needed to establish the returned representation.
        if not scalar:
            result.update(output_sensitivity="suspected", critical_unknowns=["nested_call_output_effect_unresolved"], processing_status="partial")
            result["connection"] = {"status": "partial", "reason_code": "call_consumption_only"}
    elif safe_scalar:
        result.update(source_sensitivity="not_found", output_sensitivity="not_found", critical_unknowns=[],
                      checks_complete=True, non_sensitive_basis=["fully_inspected_fixed_boolean_null_or_policy_placeholder"], processing_status="success")
        result["connection"] = {"status": "not_applicable", "reason_code": "fixed_output_no_target_sensitive_value"}
        result["processing"] = {"kind": "fixed", "steps": ["fully_inspected_literal"]}
    elif kinds:
        result.update(source_sensitivity="suspected", output_sensitivity="suspected")
        result["critical_unknowns"] = ["identifier_or_field_hint_requires_semantic_evidence"]
    if python and isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        result["processing"] = {"kind": "raw", "steps": ["direct_output_expression"]}
    elif scalar:
        result["processing"] = {"kind": "fixed", "steps": ["literal_output"]}
    if result["output_sensitivity"] == "supported":
        result["paths"] = [{"source_sensitivity": "supported", "output_sensitivity": "supported",
            "connection_supported": True, "semantics_supported": True,
            "critical_unknowns": [], "evidence_ids": []}]
    return result


def _api(index, path, call, entity):
    callee = _name(call.func)
    if callee == "print": return "python_print"
    names = {mod for mod, _ in index.imports[path].values()}
    if "structlog" in names and ("structlog" in callee or entity["level"] != "wrapper"):
        # Mixed logging libraries cannot be inferred from module membership.
        if "logging" not in names and "loguru" not in names: return "structlog"
    if "loguru" in names and "logging" not in names and "structlog" not in names: return "loguru"
    if entity["level"] == "wrapper": return "python_wrapper_unresolved"
    return "python_logging" if entity["log_detection_status"] == "confirmed" and "logging" in names else "python_logger_semantics_unverified"


def _py_parts(call, api):
    """Yield anchored output arguments, excluding levels/dispatch controls."""
    begin = 1 if _name(call.func).rsplit(".", 1)[-1] == "log" else 0
    for i, arg in enumerate(call.args):
        if i < begin: continue
        role = "message_template" if i == begin and api != "python_print" else "format_argument" if api != "python_print" else "stdout_argument"
        yield arg, "arg:" + str(i), role, "", []
    for kw in call.keywords:
        if api == "python_print":
            if kw.arg in {"sep", "end"}: yield kw.value, "kw:" + kw.arg, "stdout_separator", "", []
            continue
        if kw.arg in CONTROLS: continue
        if kw.arg == "extra":
            yield kw.value, "kw:extra", "structured_extra", "", []
        elif api in {"structlog", "loguru"}:
            yield kw.value, "kw:" + str(kw.arg), "structured_field", kw.arg or "", []
        elif kw.arg in {"msg", "message"}:
            yield kw.value, "kw:" + kw.arg, "message_template", "", []
        elif kw.arg is None:
            yield kw.value, "kw:**", "unresolved_keyword_expansion", "", ["keyword_output_selection_unresolved"]
        # Standard logging arbitrary kwargs are not presumed emitted fields.


def _dict_parts(node, key, role, field, gaps):
    if not isinstance(node, ast.Dict):
        yield node, key, role, field, gaps, []
        return
    static = {}
    dynamic = []
    for i, (k, v) in enumerate(zip(node.keys, node.values)):
        if isinstance(k, ast.Constant) and isinstance(k.value, str): static[k.value] = (i, v)
        else: dynamic.append((i, v))
    if not static and not dynamic:  # Empty object is still a real output.
        yield node, key, role, field, gaps, []
    names = sorted(_safe_name(k) for k in static)
    for name, (i, value) in sorted(static.items(), key=lambda pair: pair[1][0]):
        additional = ["later_dynamic_object_update_may_override_field"] if any(j > i for j, _ in dynamic) else []
        yield value, key + "/field:" + _safe_name(name), role + "_field", name, gaps + additional, []
    for i, value in dynamic:
        yield value, key + "/remainder:" + str(i), "object_remainder_unknown", "", gaps + ["dynamic_object_remainder"], names


def _tree_parts(syntax, node, key, role):
    if node.type != "object":
        yield node, key, role, "", [], []
        return
    known, dynamic = {}, []
    for i, child in enumerate(node.named_children):
        k, value = child.child_by_field_name("key"), child.child_by_field_name("value")
        if child.type == "pair" and k and value and k.type in {"property_identifier", "string", "string_literal"}:
            text = syntax.text(k)
            known[text.strip("\"'") if k.type != "property_identifier" else text] = (i, value)
        elif child.type == "shorthand_property_identifier": known[syntax.text(child)] = (i, child)
        else: dynamic.append((i, child))
    if not known and not dynamic: yield node, key, role, "", [], []
    names = sorted(_safe_name(k) for k in known)
    for name, (i, value) in sorted(known.items(), key=lambda pair: pair[1][0]):
        gaps = ["later_dynamic_object_update_may_override_field"] if any(j > i for j, _ in dynamic) else []
        yield value, key + "/field:" + _safe_name(name), role + "_field", name, gaps, []
    for i, value in dynamic:
        yield value, key + "/remainder:" + str(i), "object_remainder_unknown", "", ["dynamic_object_remainder"], names


def discover_file_status(path, source):
    """File-layer status, including detection hits without supported outputs."""
    language = LANGUAGES.get(PurePosixPath(path).suffix.lower(), "unsupported")
    found = detect_snapshot({path: source}, languages=list(set(LANGUAGES.values())))
    status = {"language": language, "log_count": len(found["entities"]),
              "detector_gaps": sorted({g["reason"] for g in found["gaps"]}),
              "parser_status": "unknown", "output_support": "unsupported", "reason_codes": []}
    if language == "python":
        try: ast.parse(source, filename=path)
        except (SyntaxError, ValueError, RecursionError):
            status.update(parser_status="parse_failed", reason_codes=["python_ast_parse_failed"])
        else: status.update(parser_status="python_ast", output_support="supported")
    elif language in {"javascript", "typescript", "jsx", "tsx", "go", "java"}:
        syntax = Syntax(path, source)
        if syntax.root.has_error: status.update(parser_status="parse_failed", reason_codes=["tree_sitter_parse_error"])
        else: status.update(parser_status="tree_sitter", output_support="bounded")
    else: status["reason_codes"] = ["output_ast_backend_unsupported"]
    return status


def discover_outputs(repository, event_sha, parent_sha, source_sha, side, path, source, files=None):
    """Return stable, literal-free cases for every anchored output in ``path``.

    All ``files`` must be from ``source_sha``. The caller supplies verified
    history provenance; this adapter freezes and subsequently validates bytes.
    Unparseable files have no fabricated units; callers retain file ledgers.
    """
    if not SHA.fullmatch(source_sha or "") or not SHA.fullmatch(event_sha or ""):
        raise ValueError("full_historical_sha_required")
    if parent_sha is not None and not SHA.fullmatch(parent_sha): raise ValueError("full_parent_sha_required")
    if side not in {"before", "after"}: raise ValueError("invalid_history_side")
    expected = event_sha if side == "after" else parent_sha
    if source_sha != expected: raise ValueError("history_side_source_sha_mismatch")
    snapshot = dict(files or {})
    if path in snapshot and snapshot[path] != source: raise ValueError("discovery_source_hash_mismatch")
    snapshot[path] = source
    language = LANGUAGES.get(PurePosixPath(path).suffix.lower(), "unsupported")
    found = detect_snapshot(snapshot, languages=list(set(LANGUAGES.values())))
    entities = [e for e in found["entities"] if e["path"] == path]
    index = PythonSnapshot(snapshot) if language == "python" else None
    syntax = None
    if language in {"javascript", "typescript", "jsx", "tsx", "go", "java"}:
        syntax = Syntax(path, source)
        if syntax.root.has_error: return []
    rows = []
    for entity in entities:
        if index:
            calls = [n for n in ast.walk(index.trees.get(path, ast.Module(body=[], type_ignores=[]))) if isinstance(n, ast.Call)
                     and n.lineno == entity["start_line"] and n.end_lineno == entity["end_line"] and _snippet(source, n) == entity["statement"]]
            if len(calls) != 1: continue
            call = calls[0]; log_anchor = loc(path, call); api = _api(index, path, call, entity)
            parts = [part for n, k, r, f, g in _py_parts(call, api) for part in _dict_parts(n, k, r, f, g)]
            # These flags control implicit exception/stack content, not their
            # own boolean value. The call anchor is an explicit unknown output.
            if entity["level"] == "exception" or any(k.arg in {"exc_info", "stack_info"} and not (isinstance(k.value, ast.Constant) and not k.value.value) for k in call.keywords):
                parts.append((call, "implicit:exception", "implicit_exception", "", ["exception_contents_unresolved"], []))
            scope = index.symbol(path, call)
        elif syntax:
            calls = [n for n in syntax.nodes if n.type in CALLS and n.start_point.row + 1 == entity["start_line"] and n.end_point.row + 1 == entity["end_line"]
                     and syntax.text(n).strip() == entity["statement"].strip().rstrip(";")]
            if len(calls) != 1: continue
            call = calls[0]; log_anchor = syntax.anchor(call); scope = syntax.scope(call)
            api = "console" if entity["callee"].startswith("console.") else "multilanguage_logger_semantics_unverified"
            args_node = call.child_by_field_name("arguments")
            args = list(args_node.named_children) if args_node else []
            start = 2 if language == "go" and entity["level"] == "logattrs" else 1 if language == "go" and entity["level"].endswith("context") else 0
            parts = [part for i, arg in enumerate(args) if i >= start for part in
                     _tree_parts(syntax, arg, "arg:" + str(i), "message_template" if i == start else "format_argument")]
        else:
            # C# detection exists, but no matching historical AST backend. Do
            # not invent exact output units from whole-line lexical matches.
            continue
        log_id = stable_id(repository, event_sha, parent_sha, source_sha, side, path, log_anchor)
        for node, output_key, role, field, gaps, excluded in parts:
            anchor = loc(path, node) if index else syntax.anchor(node)
            boundary = {"level": "log_record" if role.startswith("structured_extra") or api == "structlog" and role.startswith("structured_field") else "call_argument", "status": "supported"}
            if "unverified" in api or "unresolved" in api:
                boundary["status"] = "partial"
                gaps = gaps + ["logger_api_or_wrapper_output_semantics_unresolved"]
            if role == "implicit_exception": boundary = {"level": "log_record", "status": "partial"}
            case_id = stable_id(repository, event_sha, parent_sha, source_sha, side, path, log_anchor, anchor, output_key, VERSION)
            evidence_id = stable_id(case_id, "local_output_expression")
            base = _expression(node if index else (syntax, node), boundary, field, python=bool(index))
            if gaps:
                base["critical_unknowns"] = sorted(set(base["critical_unknowns"] + gaps)); base["checks_complete"] = False; base["processing_status"] = "partial"
                for p in base["paths"]: p["critical_unknowns"] += gaps; p["semantics_supported"] = False
            base["evidence_ids"] = [evidence_id]
            for p in base["paths"]: p["evidence_ids"] = [evidence_id]
            raw = _snippet(source, node) if index else syntax.text(node)
            rows.append({"case_id": case_id, "log_id": log_id, "original_log_id": entity["identity"], "repository": repository,
                "event_sha": event_sha, "parent_sha": parent_sha, "source_sha": source_sha, "side": side,
                "path": path, "language": language, "source_sha256": digest(source), "source_versions": _versions(snapshot, source_sha),
                "log_anchor": log_anchor, "output_anchor": anchor, "output_sha256": digest(raw), "scope": _safe_name(scope),
                "log_statement_sha256": digest(entity["statement"].strip().rstrip(";") if syntax else entity["statement"]),
                "output_key": output_key, "output_role": role, "field": _safe_name(field) if field else output_key,
                "api": api, "boundary": boundary, "excluded_known_fields": excluded, "split_version": VERSION,
                "detector_status": entity["log_detection_status"], "base_evidence": base,
                "limitations": sorted(set(gaps + ["formatter_handler_filter_configuration_unresolved"]))})
    return rows


def baseline_evidence(case):
    return deepcopy(case["base_evidence"])


def analyze_dfg(case, files, config):
    """Execute the existing DFG with strict frozen input/anchor validation."""
    started = time.monotonic()
    cfg = config.get("dfg", config)
    if config.get("snapshot_sha", case["source_sha"]) != case["source_sha"]:
        raise ValueError("historical_snapshot_sha_mismatch")
    versions = _versions(files, case["source_sha"])
    expected = case.get("source_versions")
    if expected is None or sorted(expected, key=lambda v: v["path"]) != versions:
        raise ValueError("historical_dependency_version_or_hash_mismatch")
    if "source_versions" in config and sorted(config["source_versions"], key=lambda v: v["path"]) != versions:
        raise ValueError("configured_dependency_version_or_hash_mismatch")
    if case["source_sha"] != (case["event_sha"] if case["side"] == "after" else case["parent_sha"]):
        raise ValueError("history_side_source_sha_mismatch")
    if digest(files.get(case["path"], "")) != case["source_sha256"]:
        raise ValueError("historical_source_hash_mismatch")
    result = {"id": case["case_id"], "repository": case["repository"], "sha": case["source_sha"], "path": case["path"],
              "field": case["field"], "scope": case.get("function_scope", case["scope"]), "language": case["language"], "side": case["side"],
              "use_anchor": case["output_anchor"], "output_expression_anchor": case["output_anchor"], "use_role": "log_argument"}
    old_case = {"id": case["case_id"], "result": result, "source_versions": versions,
        "log_start_line": case["log_anchor"]["line"], "log_end_line": case["log_anchor"]["end_line"],
        "log_statement_sha256": case["log_statement_sha256"], "history_event_id": stable_id(case["repository"], case["event_sha"], case["parent_sha"])}
    ctx = HistoricalContext(old_case, {"sha": case["source_sha"], "files": files, "backend": "frozen_history_adapter"})
    raw = ctx.raw(case["output_anchor"])
    if raw is None or digest(raw) != case["output_sha256"]: raise ValueError("historical_output_anchor_mismatch")
    if ctx.raw(case["log_anchor"]) is None or digest(ctx.raw(case["log_anchor"])) != case["log_statement_sha256"]:
        raise ValueError("historical_log_anchor_mismatch")
    if case["output_role"] in {"implicit_exception", "object_remainder_unknown", "unresolved_keyword_expansion"}:
        evidence = baseline_evidence(case)
        return {"graph": None, "evidence": evidence, "processing_status": "partial", "reason_codes": ["output_semantics_not_supported_by_dfg"], "source_versions": versions, "elapsed_seconds": time.monotonic() - started}
    if len(files) > int(cfg.get("max_files", 64)):
        evidence = baseline_evidence(case); evidence["critical_unknowns"].append("historical_file_budget_exceeded")
        return {"graph": None, "evidence": evidence, "processing_status": "partial", "reason_codes": ["historical_file_budget_exceeded"], "source_versions": versions, "elapsed_seconds": time.monotonic() - started}
    graph = build_graph(ctx, max_nodes=int(cfg.get("max_nodes", 200)), max_chars=int(cfg.get("max_chars", 24000)),
                        max_hops=int(cfg.get("max_hops", 2)), max_caller_hops=int(cfg.get("max_caller_hops", 2)))
    evidence = _graph_evidence(case, ctx, graph)
    elapsed = time.monotonic() - started
    # build_graph has no interruptible per-case deadline. Report overruns as
    # such instead of falsely claiming a hard timeout was enforced.
    if elapsed > float(cfg.get("max_seconds", cfg.get("case_timeout_seconds", 30))):
        graph["gaps"] = sorted(set(graph["gaps"] + ["case_soft_time_budget_exceeded"]))
        evidence["noncritical_unknowns"].append("case_soft_time_budget_exceeded")
    return {"graph": graph, "evidence": evidence, "processing_status": evidence["processing_status"],
            "reason_codes": graph["gaps"], "source_versions": versions, "elapsed_seconds": elapsed,
            "cache_hit": False, "actual_backend": "semantic_dfg.build_graph"}


def _graph_evidence(case, ctx, graph):
    result = baseline_evidence(case)
    nodes = {n["id"]: n for n in graph["nodes"]}
    result["evidence_ids"] += [n["evidence"]["id"] for n in graph["nodes"] if n.get("evidence")]
    incoming = {}
    for edge in graph["edges"]:
        if edge["carries_value"]: incoming.setdefault(edge["target"], []).append(edge)
    paths = []
    todo = [(graph["log_node"], [], set())]
    while todo and len(paths) < 64:
        uid, edges, seen = todo.pop()
        if uid in seen: continue
        node = nodes[uid]
        if node.get("endpoint"):
            paths.append((node, edges)); continue
        for edge in incoming.get(uid, []): todo.append((edge["source"], edges + [edge], seen | {uid}))
    added = []
    safe_paths = []
    for frontier, edges in paths:
        anchor = frontier.get("anchor")
        n = ctx.node(anchor) if anchor else None
        if n is None: continue
        local = _expression((ctx.syntax[anchor["path"]], n) if anchor.get("parser") else n,
                            case["boundary"], python=not anchor.get("parser"))
        # Formal parameters remain a boundary, even if a type/schema is known.
        if frontier.get("endpoint") == "function_parameter":
            local = _empty(case["boundary"], "formal_parameter_is_not_business_origin")
        uncertain = [e["kind"] for e in edges if e["status"] == "possible"]
        uncertain += [nodes[e["target"]]["kind"] for e in edges if nodes[e["target"]]["kind"] in {"serialization", "composite"}]
        ids = [frontier["evidence"]["id"]] if frontier.get("evidence") else []
        necessary = sorted(set(case["limitations"]) - {"formatter_handler_filter_configuration_unresolved"})
        if uncertain: necessary.append("path_transformation_semantics_unresolved")
        path = {"source_sensitivity": local["source_sensitivity"], "output_sensitivity": local["output_sensitivity"] if not uncertain else "suspected" if local["source_sensitivity"] in {"supported", "suspected"} else "unknown",
                "connection_supported": bool(edges) and not uncertain, "semantics_supported": not necessary,
                "critical_unknowns": necessary + local["critical_unknowns"], "evidence_ids": ids,
                "edge_ids": [e["id"] for e in edges], "source_anchor": anchor, "origin_category": frontier["endpoint"]}
        path["processing_steps"] = [e["kind"] for e in reversed(edges)]
        result["categories"] = sorted(set(result.get("categories", [])) | set(local.get("categories", [])))
        added.append(path)
        safe_paths.append(local["checks_complete"] and not necessary)
    result["paths"] += added
    independent = [p for p in result["paths"] if p["source_sensitivity"] == p["output_sensitivity"] == "supported" and p["connection_supported"] and p["semantics_supported"] and not p["critical_unknowns"]]
    gap_codes = sorted(set(graph["gaps"]))
    if independent:
        result.update(source_sensitivity="supported", output_sensitivity="supported", critical_unknowns=[], processing_status="success")
        result["connection"] = {"status": "supported", "reason_code": "historical_value_path"}
        result["noncritical_unknowns"] += gap_codes
        if result["processing"]["kind"] == "unknown":
            result["processing"] = {"kind": "raw", "steps": independent[0].get("processing_steps", ["historical_value_path"])}
    elif added and len(added) == len(paths) and all(safe_paths) and (not gap_codes or
            graph["input_independent_output"].get("input_independent") is True and set(gap_codes) <= {"unresolved_binding", "unresolved_scoped_binding"}) and not (set(case["limitations"]) - {"formatter_handler_filter_configuration_unresolved"}):
        result.update(output_sensitivity="not_found", critical_unknowns=[], checks_complete=True,
                      non_sensitive_basis=["all_reachable_outputs_are_inspected_fixed_policy_values"], processing_status="success")
        result["connection"] = {"status": "not_established", "reason_code": "target_connection_excluded"}
        result["processing"] = {"kind": "fixed", "steps": ["historical_path_to_inspected_fixed_output"]}
        result["noncritical_unknowns"] += gap_codes
    else:
        if any(p["source_sensitivity"] in {"supported", "suspected"} for p in added):
            result["source_sensitivity"] = "supported" if any(p["source_sensitivity"] == "supported" for p in added) else "suspected"
            result["output_sensitivity"] = "suspected"
        if any(p["connection_supported"] for p in added):
            result["connection"] = {"status": "partial", "reason_code": "bounded_origin_frontier"}
        result["critical_unknowns"] = sorted(set(result["critical_unknowns"] + gap_codes))
        result["checks_complete"] = False; result["processing_status"] = "partial"
    result["noncritical_unknowns"] = sorted(set(result["noncritical_unknowns"] + ["formatter_handler_filter_configuration_unresolved"]))
    return result
