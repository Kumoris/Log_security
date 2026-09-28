"""Classify synthetic source text; target application code is never executed."""
import pytest

from agentlog_unified.detector import detect_snapshot
from agentlog_unified.taxonomy import TAXONOMY_VERSION, annotate_entity, taxonomy_catalog


def one(body, args="x, user, password"):
    source = "import logging\nlogger = logging.getLogger(__name__)\ndef run(" + args + "):\n"
    source += "\n".join("    " + line for line in body.splitlines()) + "\n"
    return detect_snapshot({"app.py": source})["entities"][-1]


def labels(entity):
    return {(row["category"], row["subtype"]) for row in entity["taxonomy_labels"]}


@pytest.mark.parametrize("field, expected", [
    ("password", ("AUTH", "password")), ("accessToken", ("AUTH", "access_token")),
    ("api_key", ("AUTH", "api_key")), ("private_key", ("AUTH", "private_key")),
    ("email", ("PII", "email")), ("phone_number", ("PII", "phone")),
    ("full_name", ("PII", "person_name")), ("national_id", ("PII", "government_identifier")),
    ("user_id", ("QID", "user_identifier")), ("session_id", ("QID", "session_identifier")),
    ("device_id", ("QID", "device_identifier")), ("request_id", ("QID", "request_identifier")),
    ("medical_record", ("PII", "medical")), ("bank_account", ("PII", "financial")),
    ("gps_coordinates", ("PII", "precise_location")), ("face_embedding", ("PII", "biometric")),
    ("internal_url", ("CFG", "internal_endpoint")), ("file_path", ("CFG", "filesystem_path")),
])
def test_explicit_logged_field_types(field, expected):
    entity = one(f'logger.info("value", x.{field})')
    assert expected in labels(entity)
    assert entity["privacy_assessment"] in {"supported", "possible"}
    assert all(not item["runtime_confirmed"] and item["confidence"] != "high" for item in entity["taxonomy_labels"])


@pytest.mark.parametrize("field, subtype", [
    ("dateOfBirth", "birth_date"), ("user_age", "age"),
    ("gender_identity", "sex_gender"), ("ethnic_origin", "ethnicity"),
    ("religious_affiliation", "religious_belief"),
    ("education_level", "education"), ("employment_status", "employment"),
])
def test_personal_attributes_share_log_plaintext_and_json_catalog(field, subtype):
    import json
    from agentlog_unified.content_types import classify_text
    from agentlog_unified.structured_types import classify_structured
    expected = ("PII", subtype)
    entity = one(f'logger.info("record", {{"{field}": x}})')
    assert expected in labels(entity)
    assert entity["privacy_assessment"] in {"possible", "supported"}
    text = json.dumps({field: "<redacted>"})
    for result in (classify_text(text), classify_structured(text)):
        matched = [m for m in result["matches"] if (m["category"], m["subtype"]) == expected]
        assert matched and all(m["candidate_status"] == "placeholder_or_example" for m in matched)
    assert one(f'logger.info("record", {{"{field}": "<redacted>"}})')["taxonomy_labels"] == []


@pytest.mark.parametrize("expression, subtype", [
    ("user.age", "age"), ("patient.race", "ethnicity"),
    ("student.school", "education"), ("employee.job_title", "employment"),
])
def test_ambiguous_personal_leaf_requires_explicit_person_receiver(expression, subtype):
    from agentlog_unified.taxonomy import _matches
    assert ("PII", subtype) in {(r[0], r[1]) for r in _matches(expression)}
    assert ("PII", subtype) in labels(one(f'logger.info("field", {expression})'))
    leaf = expression.split(".")[-1]
    assert not _matches(leaf)
    assert not _matches("cache." + leaf)


def test_new_attribute_mentions_aggregates_and_unrelated_code_do_not_label_logs():
    from agentlog_unified.content_types import classify_text
    from agentlog_unified.taxonomy import _matches
    assert classify_text("date_of_birth gender religion employment_status")['matches'] == []
    for source in ("date_of_birth_count", "gender_enabled", "religion_type", "employee_age_limit"):
        assert not _matches(source)
    entity = one('religion = x\nif user.date_of_birth:\n    logger.info("gender and religion")')
    assert entity["taxonomy_labels"] == []
    assert entity["privacy_assessment"] == "not_supported"


def test_static_text_and_unrelated_guard_or_dependency_do_not_label_output():
    entity = one('secret = password\nif user.medical_record:\n    logger.info("password email medical_record")')
    assert entity["privacy_assessment"] == "not_supported"
    assert entity["taxonomy_labels"] == []
    assert not entity["unknown_type_review"]["needs_review"]
    assert entity["dependencies"]  # Guard is present, but it is not an output.


@pytest.mark.parametrize("body", [
    'logger.info("n=%s flag=%s", len(user), bool(password))',
    'logger.info("flag=%s", password is not None, not password)',
    'logger.info("state", "enabled" if password else "disabled")',
    'logger.info("value", {"password": "***" if x else "<redacted>"})',
    'logger.info("value", {"password": True, "email": bool(user)})',
    'logger.info("value", {"password": "<redacted>", "email": None})',
    'password = "***"\nlogger.info("value", password)',
    'obj = {"password": password}\ndel obj["password"]\nlogger.info("value", obj)',
])
def test_safe_scalars_and_verified_sanitization_do_not_create_type_candidates(body):
    entity = one(body)
    assert entity["taxonomy_labels"] == []
    assert not entity["unknown_type_review"]["needs_review"]


def test_alias_flow_combines_types_and_preserves_unknown_sibling():
    entity = one('obj = {"medical_record": user.medical_record, "email": user.email, "other": x}\nalias = obj\nlogger.info("value", alias)')
    assert {("PII", "medical"), ("PII", "email")} <= labels(entity)
    assert "x" in entity["unknown_type_review"]["unclassified_sources"]
    assert entity["unknown_type_review"]["needs_review"]


def test_unknown_parameter_and_unknown_projection_are_queued():
    for body in ['logger.info(x)', 'logger.info(user.undocumented_field)', 'logger.info(user.get("undocumented_field"))']:
        entity = one(body)
        assert entity["taxonomy_labels"] == []
        assert entity["unknown_type_review"]["needs_review"]
        assert entity["unknown_type_review"]["unclassified_sources"]


def test_receiver_context_disambiguates_name_and_id_without_tainting_all_fields():
    assert ("PII", "person_name") in labels(one('logger.info(user.name)'))
    assert ("QID", "user_identifier") in labels(one('logger.info(user.id)'))
    assert ("QID", "user_identifier") in labels(one('logger.info(user.get("id"))'))
    assert labels(one('logger.info(x.name)')) == set()


def test_named_redactor_does_not_prove_sanitization():
    entity = one('logger.info("value", unknown_redact(user.email))')
    assert ("PII", "email") in labels(entity)
    assert entity["unknown_type_review"]["needs_review"]


@pytest.mark.parametrize("expression, category", [
    ("user.request_body", "BIZ"), ("user.document_content", "BIZ"),
    ("user.environment", "CFG"), ("user.traceback", "DIAG"),
])
def test_carriers_remain_unresolved(expression, category):
    entity = one(f'logger.info("value", {expression})')
    assert category in {row["category"] for row in entity["taxonomy_labels"]}
    assert all(row["evidence_status"] == "carrier_candidate" for row in entity["taxonomy_labels"])
    assert "carrier_contents_unresolved" in entity["unknown_type_review"]["reasons"]


def test_lexical_semantics_gap_stays_in_queue():
    entity = detect_snapshot({"app.js": 'console.log("password", oddValue);'})["entities"][0]
    assert entity["taxonomy_labels"] == []
    assert "semantic_parser_unavailable" in entity["unknown_type_review"]["reasons"]


def test_catalog_and_old_entity_backfill_are_versioned_idempotent():
    catalog = taxonomy_catalog()
    assert {row["category"] for row in catalog["categories"]} == {"AUTH", "PII", "QID", "BIZ", "CFG", "DIAG"}
    entity = {"privacy_assessment": "possible", "parser_status": "python_ast", "source_to_sink": [
        {"source": "access_token", "basis": "identifier_only", "types": ["credential"]}],
        "missing_evidence": ["runtime_reachability_and_output_access_unverified"]}
    annotated = annotate_entity(entity)
    assert annotated["taxonomy_version"] == catalog["taxonomy_version"] == TAXONOMY_VERSION
    assert ("AUTH", "access_token") in labels(annotated)
    assert "taxonomy_version" not in entity
    assert annotate_entity(annotated) == annotated


def test_new_sensitive_subtypes_survive_coarse_assessment():
    entity = one('logger.info("value", {"medical_record": x, "salary": x, "latitude": x, "biometric_data": x})')
    assert {"medical_data", "financial_data", "precise_location", "biometric_data"} <= set(entity["data_types"])
    assert entity["privacy_assessment"] == "supported"


def test_unknown_model_field_is_not_a_safe_negative():
    source = "from dataclasses import dataclass\nimport logging\n@dataclass\nclass Record:\n    odd: str\ndef run(x: Record):\n    logging.info(x)\n"
    entity = detect_snapshot({"app.py": source})["entities"][0]
    assert entity["privacy_assessment"] == "unknown"
    assert entity["unknown_type_review"]["needs_review"]


def test_legacy_negative_with_unresolved_output_semantics_still_needs_context():
    entity = annotate_entity({"privacy_assessment": "not_supported", "parser_status": "python_ast",
        "missing_evidence": ["object_representation_unresolved", "runtime_reachability_and_output_access_unverified"]})
    assert entity["unknown_type_review"]["needs_review"]
    assert "bounded_semantics_incomplete" in entity["unknown_type_review"]["reasons"]


@pytest.mark.parametrize("body", [
    'logger.info("record", medical_record=x)',
    'child = logger.bind(medical_record=x)\nchild.info("record")',
    'record = dict(medical_record=x)\nlogger.info("record", record)',
    'record = dict({}, **{"medical_record": x})\nlogger.info("record", record)',
])
def test_structured_keyword_fields_preserve_source_type(body):
    source = "import structlog\nlogger=structlog.get_logger()\ndef run(x):\n"
    source += "\n".join("    " + line for line in body.splitlines()) + "\n"
    entity = detect_snapshot({"app.py": source})["entities"][-1]
    assert ("PII", "medical") in labels(entity)
    assert any(flow["source"] == "medical_record" and flow["basis"] == "explicit_output_field" for flow in entity["source_to_sink"])
    assert all(not row["runtime_confirmed"] for row in entity["taxonomy_labels"])


@pytest.mark.parametrize("body", [
    'logger.info({"password": {"token": "***"}})',
    'logger.info({"password": [{"token": "<redacted>"}, None]})',
    'logger.info({"password": []})',
    'logger.info({"password": {}})',
    'obj = dict({"email": x.email}, email="<redacted>")\nlogger.info(obj)',
    'logger.info(dict(password=dict(token="***")))',
])
def test_complete_nested_redaction_does_not_reintroduce_sensitive_outer_field(body):
    entity = one(body)
    assert entity["privacy_assessment"] == "not_supported"
    assert labels(entity) == set()
    assert not entity["unknown_type_review"]["needs_review"]


def test_partially_unknown_container_and_unknown_transform_are_not_proven_masked():
    entity = one('logger.info({"password": {"token": "***", "other": x}})')
    assert ("AUTH", "password") in labels(entity)
    assert entity["unknown_type_review"]["needs_review"]
    transformed = one('logger.info({"password": external("***")})')
    assert transformed["privacy_assessment"] != "not_supported"
    assert transformed["unknown_type_review"]["needs_review"]


def test_literal_payload_name_is_a_weak_candidate_without_scanning_fixed_prose():
    entity = one('email = "synthetic-person@example.invalid"\ncopy = email\nlogger.info(copy)')
    assert entity["privacy_assessment"] == "possible"
    assert ("PII", "email") in labels(entity)
    assert all(row["confidence"] == "low" and not row["runtime_confirmed"] for row in entity["taxonomy_labels"])
    assert entity["unknown_type_review"]["needs_review"]
    for body in ['logger.info("synthetic-person@example.invalid")',
                 'email_message = "The email field is disabled"\nlogger.info(email_message)',
                 'emailMessage = "The email field is disabled"\nlogger.info(emailMessage)',
                 'email = "***"\nlogger.info(email)']:
        fixed = one(body)
        assert fixed["privacy_assessment"] == "not_supported"
        assert labels(fixed) == set()
        assert not fixed["unknown_type_review"]["needs_review"]
