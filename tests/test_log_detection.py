from agentlog_unified.detector import detect_snapshot, match_entities


def logs(code, **files):
    return detect_snapshot({"app.py": code, **files})["entities"]


def test_multiline_structured_and_math_and_alias():
    code = '''import logging as lg
import math
from logging import getLogger as make_logger
logger = make_logger(__name__)
def run():
    validator = {"password": "DUMMY_RESEARCH_SECRET_NOT_VALID", "token_count": 9}
    math.log(3)
    logger.info(
        "auth",
        extra={"validator": validator},
    )
'''
    entities = logs(code)
    assert len(entities) == 1
    entity = entities[0]
    assert entity["start_line"] == 8 and entity["end_line"] == 11
    assert entity["log_detection_status"] == "confirmed"
    assert entity["privacy_assessment"] == "supported"
    assert "credential" in entity["data_types"]
    assert any(d["symbol"] == "validator" for d in entity["dependencies"])
    assert "extra={" in entity["statement"]


def test_safe_logs_are_retained_and_count_is_not_credential():
    entities = logs('''import logging
logger = logging.getLogger(__name__)
def run(token_count: int):
    logger.info("token count=%s", token_count)
    logger.info("started")
    print("hello")
''')
    assert len(entities) == 3
    assert entities[0]["privacy_assessment"] == "not_supported"
    assert all("credential" not in e["data_types"] for e in entities)
    assert entities[-1]["log_detection_status"] == "possible"


def test_one_hop_import_fix_changes_unchanged_log_dependency():
    code = '''import logging
from serialization import serialize
logger = logging.getLogger(__name__)
def run():
    user = {"id": 3, "password": "DUMMY_RESEARCH_SECRET_NOT_VALID"}
    logger.info("user %s", serialize(user))
'''
    before = logs(code, **{"serialization.py": "def serialize(user):\n    return user\n"})
    after = logs(code, **{"serialization.py": 'def serialize(user):\n    return {"id": user["id"]}\n'})
    assert before[0]["privacy_assessment"] == "supported"
    assert after[0]["privacy_assessment"] == "not_supported"
    assert any(d["path"] == "serialization.py" for d in before[0]["dependencies"])
    pair = match_entities(before, after)[0]
    assert pair["change_kind"] == "modified"
    assert pair["before"]["statement"] == pair["after"]["statement"]


def test_sanitizer_name_and_nested_field_are_not_proof_of_safety():
    code = '''import logging
logger = logging.getLogger(__name__)
def sanitize(x):
    return {"id": x["id"], "nested": x["nested"]}
def run():
    user = {"id": 1, "nested": {"password": "DUMMY_RESEARCH_SECRET_NOT_VALID"}}
    logger.info("data %s", sanitize(user))
    logger.info("external %s", unknown_sanitize(user))
'''
    entities = logs(code)
    assert len(entities) == 2
    assert all(e["privacy_assessment"] == "supported" for e in entities)
    assert "unverified_named_sanitizer:unknown_sanitize" in entities[1]["existing_sanitization"]


def test_vars_and_later_activated_model_field():
    code = '''import logging
from models import User
logger = logging.getLogger(__name__)
def run(user: User):
    logger.info("user %s", vars(user))
'''
    before = logs(code, **{"models.py": "from dataclasses import dataclass\n@dataclass\nclass User:\n    id: int\n"})
    after = logs(code, **{"models.py": "from dataclasses import dataclass\n@dataclass\nclass User:\n    id: int\n    password: str\n"})
    assert before[0]["privacy_assessment"] == "not_supported"
    assert after[0]["privacy_assessment"] == "supported"
    assert any(d["kind"] == "data_model" for d in after[0]["dependencies"])
    assert match_entities(before, after)[0]["change_kind"] == "modified"


def test_logger_adapter_extra_and_trigger_change():
    code = '''import logging
base = logging.getLogger(__name__)
logger = logging.LoggerAdapter(base, {"authorization": "DUMMY_RESEARCH_SECRET_NOT_VALID"})
def run(enabled):
    if enabled:
        logger.debug("start")
'''
    entity = logs(code)[0]
    assert entity["privacy_assessment"] == "supported"
    assert entity["log_detection_status"] == "confirmed"
    assert "condition:enabled" in entity["trigger_conditions"]
    assert any(d["kind"] == "condition" for d in entity["dependencies"])


def test_level_changes_and_argument_deletion_match_one_entity():
    before = logs('logger.info(\n "auth",\n extra={"password": password}\n)\n')
    after = logs('logger.debug(\n "auth"\n)\n')
    assert before[0]["identity"] == after[0]["identity"]
    pairs = match_entities(before, after)
    assert len(pairs) == 1 and pairs[0]["change_kind"] == "modified"
    assert match_entities(before, [])[0]["change_kind"] == "deleted"


def test_duplicate_templates_are_ambiguous():
    before = logs('logger.info("same", a)\nlogger.info("same", b)\n')
    after = logs('logger.info("same", b)\n')
    pairs = match_entities(before, after)
    assert all(pair["match_status"] == "ambiguous" for pair in pairs)


def test_javascript_multiline_lexical_fallback_is_explicit():
    result = detect_snapshot({"app.ts": '''const user = {password: "DUMMY_RESEARCH_SECRET_NOT_VALID"};
// logger.info("not a call")
const message = "logger.info('not a call')";
logger.info(
  {request: user},
  "received"
);
Math.log(5);
'''})
    assert len(result["entities"]) == 1
    entity = result["entities"][0]
    assert entity["parser_status"] == "lexical_only"
    assert entity["end_line"] == 7
    assert entity["privacy_assessment"] == "possible"
    assert entity["dependencies"]
    assert result["gaps"]


def test_invalid_python_is_gap_not_no_logs():
    result = detect_snapshot({"app.py": 'def broken(:\n    logger.info(\n "x",\n password\n)\n'})
    assert result["entities"][0]["parser_status"] == "lexical_only"
    assert any(g["reason"] == "python_ast_parse_failed" for g in result["gaps"])


def test_nested_relative_import_and_explicit_jsx_config():
    result = detect_snapshot({"pkg/app.py": 'import logging\nfrom .helpers import project\nlog = logging.getLogger(__name__)\nlog.info("x", project({"password": "DUMMY_RESEARCH_SECRET_NOT_VALID", "id": 1}))\n', "pkg/helpers.py": 'def project(x):\n    return {"id": x["id"]}\n', "app.jsx": 'console.log("x");'})
    assert len(result["entities"]) == 1
    assert result["entities"][0]["privacy_assessment"] == "not_supported"
    assert len(detect_snapshot({"app.jsx": 'console.log("x");'}, ["jsx"])["entities"]) == 1


def test_same_scope_field_mutation_is_a_dependency():
    entity = logs('''import logging
logger = logging.getLogger(__name__)
def run():
    data = {"id": 2}
    data["password"] = "DUMMY_RESEARCH_SECRET_NOT_VALID"
    logger.info("snapshot %s", data)
''')[0]
    assert entity["privacy_assessment"] == "supported"
    assert any(d["kind"] == "argument_mutation" for d in entity["dependencies"])


def test_unresolved_field_allowlist_is_not_certified_safe():
    entity = logs('''import logging
logger = logging.getLogger(__name__)
def project(user):
    return {"nested": user["nested"]}
def run(user):
    logger.info("user %s", project(user))
''')[0]
    assert entity["privacy_assessment"] == "unknown"
    assert "field_runtime_value_unknown" in entity["missing_evidence"]


def test_object_representation_unknown_but_vars_is_explicit():
    entities = logs('''import logging
logger = logging.getLogger(__name__)
class User:
    password: str
    def __repr__(self):
        return "User"
def run(user: User):
    logger.info("object %s", user)
    logger.info("fields %s", vars(user))
''')
    assert entities[0]["privacy_assessment"] == "possible"
    assert entities[1]["privacy_assessment"] == "supported"


def test_exception_output_and_literal_credentials_have_evidence():
    entities = logs('''import logging
logger = logging.getLogger(__name__)
logger.exception("failure")
logger.info("password=DUMMY_RESEARCH_SECRET_NOT_VALID")
logger.info("password=%s", "***")
''')
    assert entities[0]["privacy_assessment"] == "possible"
    assert "exception_data" in entities[0]["data_types"]
    assert entities[1]["privacy_assessment"] == "supported"
    assert entities[2]["privacy_assessment"] == "not_supported"


def test_numeric_credential_is_not_made_safe_by_int_conversion():
    entities = logs('''import logging
logger = logging.getLogger(__name__)
def run(token: int):
    logger.info("numeric token %s", int(token))
''')
    assert entities[0]["privacy_assessment"] == "possible"
    assert "credential" in entities[0]["data_types"]
