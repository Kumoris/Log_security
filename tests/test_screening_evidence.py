"""Adapter tests run framework code only; historical source is never imported."""
from copy import deepcopy
import json
from xml.etree import ElementTree

import pytest

from agentlog_unified.screening_evidence import discover_outputs, analyze_dfg, baseline_evidence, discover_file_status
from agentlog_unified.semantic_dfg import svg

HEADER = "import logging\nlogger = logging.getLogger(__name__)\n"
A, B = "a" * 40, "b" * 40


def cases(code, extra=None, side="after", sha=A, parent=None, path="app.py"):
    files = {path: code, **(extra or {})}
    return discover_outputs("fixture/repo", sha, parent, sha if side == "after" else parent, side, path, code, files), files


def test_constants_format_parameters_and_controls_are_distinct_outputs():
    rows, files = cases(HEADER + 'logger.info("done", extra={"user_id": value}, stacklevel=2, exc_info=False)\nlogger.log(20, "v=%s", value)\n')
    assert [r["output_key"] for r in rows] == ["arg:0", "kw:extra/field:user_id", "arg:1", "arg:2"]
    assert rows[1]["boundary"] == {"level": "log_record", "status": "supported"}
    assert baseline_evidence(rows[0])["checks_complete"]
    assert rows[1]["base_evidence"]["output_sensitivity"] == "suspected"
    assert len({r["case_id"] for r in rows}) == 4


def test_direct_sensitive_literal_zero_hop_and_no_secret_in_artifacts():
    rows, files = cases(HEADER + 'logger.warning("password=SYNTHETIC_ONLY_VALUE_492")\n')
    assert rows[0]["base_evidence"]["output_sensitivity"] == "supported"
    out = analyze_dfg(rows[0], files, {})
    assert out["graph"]["origin_counts"] == {"constant": 1}
    assert out["evidence"]["paths"][0]["connection_supported"]
    assert "SYNTHETIC_ONLY_VALUE_492" not in json.dumps([rows, out])
    ElementTree.fromstring(svg(out["graph"]))


def test_unknown_function_or_boolean_operation_cannot_inherit_literal_output():
    for expr in ['mask("password=SYNTHETIC_VALUE")', 'False and "password=SYNTHETIC_VALUE"']:
        rows, files = cases(HEADER + 'logger.info(' + expr + ')\n')
        assert rows[0]["base_evidence"]["output_sensitivity"] == "suspected"
        out = analyze_dfg(rows[0], files, {})
        assert not any(p["output_sensitivity"] == "supported" and p["semantics_supported"] and not p["critical_unknowns"] for p in out["evidence"]["paths"])


def test_known_fields_and_unknown_remainder_do_not_duplicate_parent():
    rows, _ = cases(HEADER + 'logger.info({"safe": True, **unknown, "other": False})\n')
    assert len(rows) == 3
    assert {r["output_role"] for r in rows} == {"message_template_field", "object_remainder_unknown"}
    remainder = next(r for r in rows if r["output_role"] == "object_remainder_unknown")
    assert set(remainder["excluded_known_fields"]) == {"safe", "other"}
    safe = next(r for r in rows if r["field"] == "safe")
    assert "later_dynamic_object_update_may_override_field" in safe["base_evidence"]["critical_unknowns"]
    assert not safe["base_evidence"]["checks_complete"]


def test_versions_dependencies_and_output_anchors_fail_closed():
    rows, files = cases(HEADER + 'from helper import relay\nlogger.info(relay(False))\n', {"helper.py": 'def relay(value):\n    return value\n'})
    analyze_dfg(rows[0], files, {})
    with pytest.raises(ValueError, match="dependency_version_or_hash"):
        analyze_dfg(rows[0], {**files, "helper.py": "def relay(value):\n    return True\n"}, {})
    with pytest.raises(ValueError, match="snapshot_sha"):
        analyze_dfg(rows[0], files, {"snapshot_sha": B})
    modified = deepcopy(rows[0]); modified["output_anchor"]["column"] += 1
    with pytest.raises(ValueError, match="output_anchor"):
        analyze_dfg(modified, files, {})
    with pytest.raises(ValueError, match="history_side_source_sha"):
        discover_outputs("fixture/repo", A, B, A, "before", "app.py", files["app.py"])


def test_function_scope_and_side_are_isolated_with_real_dfg():
    source = HEADER + 'def first(value):\n    logger.info(value)\ndef second(value):\n    value=False\n    logger.info(value)\n'
    rows, files = cases(source)
    first = analyze_dfg(rows[0], files, {})["graph"]
    second = analyze_dfg(rows[1], files, {})["graph"]
    assert first["origin_counts"] == {"function_parameter": 1}
    assert second["origin_counts"] == {"constant": 1}
    before = discover_outputs("fixture/repo", A, B, B, "before", "app.py", source)
    assert {r["case_id"] for r in rows}.isdisjoint(r["case_id"] for r in before)
    assert not first["complete_external_origin"]


def test_cross_file_call_context_and_fixed_helper_preserves_actual_evidence():
    code = HEADER + 'from helper import relay\nlogger.info(relay(False))\nlogger.info(relay("password=SYNTHETIC_FIXTURE"))\n'
    rows, files = cases(code, {"helper.py": 'def relay(value):\n    return value\n'})
    first = analyze_dfg(rows[0], files, {})
    second = analyze_dfg(rows[1], files, {})
    assert {"actual_to_formal", "return_value", "call_return"} <= {e["kind"] for e in first["graph"]["edges"]}
    assert first["evidence"]["output_sensitivity"] != "supported"
    assert second["evidence"]["output_sensitivity"] == "supported"
    fixed, ff = cases(HEADER + 'from helper import mask\nlogger.info(mask(secret))\n', {"helper.py": 'def mask(value):\n    return False\n'})
    result = analyze_dfg(fixed[0], ff, {})
    assert not any(e["kind"] == "actual_to_formal" for e in result["graph"]["edges"])
    assert result["evidence"]["output_sensitivity"] == "not_found"


def test_type_edges_never_establish_value_origin_and_budget_keeps_unknown():
    rows, files = cases(HEADER + 'from pydantic import EmailStr\ndef emit(data: EmailStr):\n    logger.info(data)\n')
    out = analyze_dfg(rows[0], files, {})
    assert any(e["kind"] == "metadata" and not e["carries_value"] for e in out["graph"]["edges"])
    assert out["evidence"]["source_sensitivity"] != "supported"
    truncated = analyze_dfg(rows[0], files, {"max_nodes": 1})
    assert "graph_node_budget_exceeded" in truncated["reason_codes"]
    assert not truncated["evidence"]["checks_complete"]


def test_js_and_go_constant_templates_are_not_excluded():
    for path, source in [("app.js", 'console.log("password=SYNTHETIC_FIXTURE", value);'),
                         ("app.go", 'package app\nimport "log"\nfunc emit(value string) { log.Printf("v=%s", value) }\n')]:
        rows, files = cases(source, path=path)
        assert len(rows) == 2
        assert rows[0]["output_role"] == "message_template"
        out = analyze_dfg(rows[0], files, {})
        assert out["graph"]["nodes"]
        assert "SYNTHETIC_FIXTURE" not in json.dumps(out)


def test_parse_failure_and_unsupported_csharp_have_no_fabricated_output():
    assert cases('def broken(:\n logger.info(secret)\n')[0] == []
    assert cases('class A { void M() { logger.Info("v"); } }', path="app.cs")[0] == []
    assert discover_file_status("app.py", "def broken(:")["parser_status"] == "parse_failed"
    assert discover_file_status("app.cs", 'class A { void M() { logger.Info("v"); } }')["output_support"] == "unsupported"
    assert discover_file_status("app.js", "console.log(")["parser_status"] == "parse_failed"


def test_js_partial_object_splits_without_parent_duplicate():
    rows, files = cases('console.log({ok: true, ...other, secret: value});', path="app.js")
    assert len(rows) == 3
    assert rows[-1]["output_role"] == "object_remainder_unknown"
    assert set(rows[-1]["excluded_known_fields"]) == {"ok", "secret"}
    assert analyze_dfg(rows[1], files, {})["graph"]["nodes"]
