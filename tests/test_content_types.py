"""Synthetic content candidates: never use or activate real credentials."""
import json
import subprocess
import sys

import pytest

from agentlog_unified.content_types import MAX_SOURCE_CHARS, classify_text, detector_catalog
from agentlog_unified.taxonomy import RULES


FIELDS = {"start", "end", "category", "subtype", "rule", "basis", "confidence", "value_status", "candidate_status"}


def labels(text):
    return {(row["category"], row["subtype"]) for row in classify_text(text)["matches"]}


def test_literal_shapes_have_only_safe_labels_and_character_offsets():
    email = "fixture-user@example.invalid"
    token = "ghp_" + "0123456789" * 3
    text = "中文🙂 " + email + " " + token + " 192.0.2.17"
    result = classify_text(text)
    assert not result["truncated"]
    assert labels(text) == {("PII", "email"), ("AUTH", "access_token"), ("QID", "network_identifier")}
    for row in result["matches"]:
        assert set(row) == FIELDS
        assert row["confidence"] == "low"
        assert 0 <= row["start"] < row["end"] <= len(text)
    email_row = next(row for row in result["matches"] if row["subtype"] == "email")
    assert (email_row["start"], email_row["end"]) == (4, 4 + len(email))
    assert email_row["value_status"] == "placeholder_or_example"
    serialized = json.dumps(result)
    assert email not in serialized and token not in serialized and "192.0.2.17" not in serialized


def test_supported_auth_shapes_are_formats_not_credential_validation():
    jwt = "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12
    text = "\n".join([jwt, "Bearer " + jwt, "sk-" + "0" * 24,
                      "AKIA" + "A" * 16, "https://fixture-user:synthetic-value@host.invalid/",
                      "-----BEGIN PRIVATE KEY-----\nSYNTHETIC NOT VALID\n-----END PRIVATE KEY-----"])
    assert labels(text) == {("AUTH", name) for name in ("access_token", "api_key", "credential_bundle", "authorization_header", "private_key")}
    private = next(row for row in classify_text(text)["matches"] if row["subtype"] == "private_key")
    assert private["candidate_status"] == "placeholder_or_example"
    assert private["basis"] == "literal_shape"
    assert labels("-----BEGIN PRIVATE KEY-----\nunfinished") == set()


@pytest.mark.parametrize("text", [
    "Do not log passwords, email, medical records or private keys.",
    "The userName variable contains a name, and customer_id is a user identifier.",
    "Support password reset. No values are included here.",
    "ordinary_count=12 status=ready other_field='hello'",
    "999.12.3.4 10.2.3.4.5",
])
def test_mentions_generic_assignments_and_invalid_ips_are_not_literal_values(text):
    assert classify_text(text) == {"matches": [], "truncated": False}


def test_named_value_reference_carrier_unknown_and_example_are_separate():
    text = '\n'.join([
        'password="SYNTHETIC-NOT-VALID"',
        'email=user.email',
        'medical="fixture clinical note"',
        'request_body="arbitrary content"',
        'sensitive_data="undetermined"',
        'api_key="${SERVICE_KEY}"',
    ])
    rows = classify_text(text)["matches"]
    lookup = {row["subtype"]: row for row in rows}
    assert lookup["password"]["candidate_status"] == "placeholder_or_example"
    assert lookup["email"]["candidate_status"] == "identifier_reference"
    assert lookup["email"]["value_status"] == "opaque"
    assert lookup["medical"]["candidate_status"] == "named_value_candidate"
    assert lookup["medical"]["basis"] == "named_value_hint"
    assert lookup["request_body"]["candidate_status"] == "carrier_candidate"
    assert lookup["request_body"]["value_status"] == "opaque"
    assert lookup[None]["candidate_status"] == "unknown_named_value"
    assert lookup[None]["category"] is None
    assert lookup["api_key"]["candidate_status"] == "identifier_reference"
    assert "arbitrary content" not in json.dumps(rows)
    assert "sensitive_data" not in json.dumps(rows)


@pytest.mark.parametrize("value", ["person@example.com", "person@example.org", "person@example.net", "person@example.test", "person@unit.invalid"])
def test_reserved_example_addresses_are_not_promoted_to_real_values(value):
    result = classify_text(value)
    assert len(result["matches"]) == 1
    assert result["matches"][0]["candidate_status"] == "placeholder_or_example"


def test_quoted_keys_unicode_prefix_template_and_aggregate_name():
    text = '消息: {"phone": "+1 555 0100", "user_id": 42, "email": "{Email}"}\npassword_count=3'
    rows = classify_text(text)["matches"]
    assert {row["subtype"] for row in rows} == {"phone", "user_identifier", "email"}
    phone = next(row for row in rows if row["subtype"] == "phone")
    assert text[phone["start"]:phone["end"]] == "+1 555 0100"
    assert next(row for row in rows if row["subtype"] == "email")["value_status"] == "opaque"


def test_numeric_names_are_only_hints_and_bearer_identifier_is_opaque():
    rows = classify_text("latitude=0.5 user_id=123 Bearer ACCESS_TOKEN")["matches"]
    assert {row["subtype"] for row in rows} == {"precise_location", "user_identifier", "authorization_header"}
    assert next(row for row in rows if row["subtype"] == "authorization_header")["candidate_status"] == "identifier_reference"
    assert all(row["basis"] != "literal_shape" for row in rows)


def test_overlapping_type_hint_dedup_and_explicit_cap():
    text = 'email="person@example.invalid" user_id=42'
    assert len(classify_text(text)["matches"]) == 2
    assert classify_text(text, max_matches=1)["truncated"]
    assert len(classify_text(text, max_matches=1)["matches"]) == 1
    assert classify_text(text, max_matches=0) == {"matches": [], "truncated": True}
    assert classify_text("plain words", max_matches=0) == {"matches": [], "truncated": False}
    assert not classify_text(text, max_matches=2)["truncated"]


@pytest.mark.parametrize("cap", [-1, 1.5, True, "1"])
def test_invalid_cap_is_rejected(cap):
    with pytest.raises(ValueError):
        classify_text("", max_matches=cap)


def test_input_bounds_and_no_echo_in_errors():
    with pytest.raises(TypeError, match="text must be a string"):
        classify_text(None)
    with pytest.raises(ValueError, match="character bound"):
        classify_text("x" * (MAX_SOURCE_CHARS + 1))


def test_catalog_matches_actual_rule_boundary():
    catalog = detector_catalog()
    assert catalog["content_detector_version"] == "1.2.0"
    assert catalog["taxonomy_subtype_count"] == 49
    assert catalog["literal_shape_subtype_count"] == 7
    assert catalog["named_hint_subtype_count"] == len(RULES) == 44
    assert "7 subtypes have limited literal shapes; 44 have identifier-key hints. The 49-subtype taxonomy is not fully detectable." in catalog["limitations"]
    assert sum(row["literal_shape_subset"] for row in catalog["subtypes"]) == 7
    assert all(row["context_or_review_required"] for row in catalog["subtypes"])
    assert {row["subtype"] for row in catalog["subtypes"] if not row["named_hint_available"]} == {
        "unspecified_personal_information", "unspecified_linkable_identifier", "unclassified_object",
        "unclassified_content", "unclassified_internal_resource",
    }


def test_bounded_scans_do_not_retry_unclosed_envelopes_or_long_tokens():
    # A process deadline catches pathological regex retries without a fragile
    # machine-speed assertion. Only synthetic adversarial text is constructed.
    script = '''from agentlog_unified.content_types import classify_text
for value in ["a." * 400000, "-----BEGIN PRIVATE KEY-----\\n" * 20000,
              "ghp_" + "A" * 500000, 'password="' + "a" * 500000]:
    result = classify_text(value, max_matches=3)
    assert result == {"matches": [], "truncated": False}
'''
    subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, timeout=15)
