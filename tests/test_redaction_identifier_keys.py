"""Named-key redaction uses the same bounded hints as classification."""
from agentlog_unified.storage import redact


def test_equivalent_sensitive_keys_redact_nested_opaque_values():
    value = "opaque-fixture-value"
    keys = ("password", "APIKey", "HTTPAuthorization", "AccessToken", "EMail", "user.Email")
    for key in keys:
        assert redact({key: value}) == {key: "<REDACTED:VALUE>"}
        assert redact({key: [value, "", None, 4]}) == {key: ["<REDACTED:VALUE>", "", None, 4]}
    assert redact({"wrapper": {"APIKey": value}}) == {"wrapper": {"APIKey": "<REDACTED:VALUE>"}}


def test_non_sensitive_projections_aggregates_and_provenance_are_preserved():
    value = "opaque-fixture-value"
    for key in ("APIKey.id", "password.name", "HTTPAuthorizationCount", "APIKEYCount", "full_name", "source_row", "candidate_status"):
        assert redact({key: value}) == {key: value}
    assert redact({"semantic_statement": value})["semantic_statement"].startswith("<SEMANTIC_SHA256:")
