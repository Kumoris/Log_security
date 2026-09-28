"""Regression checks parse synthetic strings; they never run target application code."""
import pytest

from agentlog_unified.detector import detect_snapshot


def entities(body):
    source = "import logging\nlogger = logging.getLogger(__name__)\ndef run(user, flag, key):\n" + "\n".join("    " + line for line in body.splitlines()) + "\n"
    return detect_snapshot({"app.py": source})["entities"]


@pytest.mark.parametrize("mutation", [
    'obj.update({"password": user.password})',
    'obj.update(password=user.password)',
    'obj["password"] = user.password',
    'obj |= {"password": user.password}',
    'obj.setdefault("password", user.password)',
])
def test_mutation_introduces_credential_and_preserves_evidence(mutation):
    log = entities('obj = {}\n' + mutation + '\nlogger.info("value", obj)')[0]
    assert log["privacy_assessment"] == "supported"
    assert "credential" in log["data_types"]
    assert any(e["basis"] == "explicit_sensitive_access" and e["source"] == "user.password" for e in log["source_to_sink"])
    assert any(d["kind"] == "argument_mutation" for d in log["dependencies"])


@pytest.mark.parametrize("removal", [
    'del obj["password"]',
    'obj.pop("password")',
    'obj.clear()',
    'obj.update({"password": "***"})',
    'obj["password"] = "***"',
])
def test_removal_affects_only_later_log(removal):
    logs = entities('obj = {"password": user.password}\nlogger.info("before", obj)\n' + removal + '\nlogger.info("after", obj)')
    assert logs[0]["privacy_assessment"] == "supported"
    assert logs[1]["privacy_assessment"] == "not_supported"


def test_simple_aliases_share_mutations_but_rebinding_does_not():
    logs = entities('obj = {}\nalias = obj\nalias.update({"password": user.password})\nlogger.info("shared", obj)\nobj = {}\nlogger.info("rebound", obj)\nlogger.info("old", alias)')
    assert [log["privacy_assessment"] for log in logs] == ["supported", "not_supported", "supported"]
    assert any(d["symbol"] == "alias" for d in logs[0]["dependencies"])


def test_nested_dictionary_deletion_and_augmented_value():
    logs = entities('obj = {"nested": {"password": user.password}}\ndel obj["nested"]["password"]\nlogger.info("removed", obj)\ntext = "prefix"\ntext += user.password\nlogger.info("added", text)')
    assert logs[0]["privacy_assessment"] == "not_supported"
    assert logs[1]["privacy_assessment"] == "supported"


@pytest.mark.parametrize("operation", ['obj.update(user)', 'obj[key] = user', 'obj.custom_mutation()', 'unknown_mutate(obj)', 'service.mutate(obj)'])
def test_unknown_mutation_is_never_a_safe_negative(operation):
    log = entities('obj = {}\n' + operation + '\nlogger.info("value", obj)')[0]
    assert log["privacy_assessment"] != "not_supported"
    assert log["missing_evidence"]


def test_conditional_redaction_keeps_possible_original_flow():
    log = entities('obj = {"password": user.password}\nif flag:\n    obj.clear()\nlogger.info("value", obj)')[0]
    assert log["privacy_assessment"] == "supported"
    assert "conditional_mutation_unresolved" in log["missing_evidence"]


def test_conditional_assignment_cannot_replace_unknown_with_safe_value():
    log = entities('obj = user\nif flag:\n    obj = {}\nlogger.info("value", obj)')[0]
    assert log["privacy_assessment"] != "not_supported"
    assert "conditional_assignment_unresolved" in log["missing_evidence"]


def test_same_line_ordering_and_source_chain():
    logs = entities('obj = {}; obj.update({"password": user.password}); logger.info("before", obj); obj.clear(); logger.info("after", obj)')
    assert [log["privacy_assessment"] for log in logs] == ["supported", "not_supported"]


def test_else_polarity_loop_and_condition_definition_are_dependencies():
    logs = entities('enabled = flag\nif enabled:\n    logger.info("on")\nelse:\n    logger.info("off")\nfor item in user:\n    logger.info("item", item)')
    assert "condition:enabled" in logs[0]["trigger_conditions"]
    assert "condition:not (enabled)" in logs[1]["trigger_conditions"]
    assert any(d["symbol"] == "enabled" and d["kind"] == "argument_definition" for d in logs[0]["dependencies"])
    assert any(t.startswith("for:") for t in logs[2]["trigger_conditions"])
    assert any(d["kind"] == "loop_iterable" for d in logs[2]["dependencies"])


def test_child_logger_binding_and_ast_semantics_survive_formatting():
    a = entities('child = logger.getChild("component")\nchild.info("value", user)')[0]
    b = entities('child = logger.getChild("component")\nchild.info(\n    "value", user\n)')[0]
    assert a["log_detection_status"] == "confirmed"
    assert a["semantic_statement"] == b["semantic_statement"]
    assert a["statement"] != b["statement"]


def test_logger_alias_inherits_adapter_context_fields():
    log = entities('adapter = logging.LoggerAdapter(logger, {"password": user.password})\nalias = adapter\nalias.info("value")')[0]
    assert log["privacy_assessment"] == "supported"
    assert {"alias", "adapter"} <= {d["symbol"] for d in log["dependencies"] if d["kind"] == "logger_binding"}


def test_one_hop_mutating_projection_retains_log_argument_semantics():
    source = 'import logging\ndef project(value):\n    value.pop("password")\n    return value\nlogging.info("value", project({"password": "DUMMY_NOT_VALID", "id": 1}))\n'
    log = detect_snapshot({"app.py": source})["entities"][0]
    assert log["privacy_assessment"] == "not_supported"
    assert any(d["kind"] == "argument_mutation" for d in log["dependencies"])


def test_javascript_multiline_keeps_conservative_semantic_text():
    source = 'console.log(\n "value",\n {password: user.password}\n);\n'
    log = detect_snapshot({"app.js": source})["entities"][0]
    assert log["end_line"] == 4
    assert log["semantic_statement"] == log["statement"].strip()
    assert log["privacy_assessment"] == "possible"
