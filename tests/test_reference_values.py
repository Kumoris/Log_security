"""Shared bounded identifier syntax; synthetic references never get resolved."""
import json

import pytest

from agentlog_unified.content_types import _REFERENCE, classify_text
from agentlog_unified.structured_types import classify_structured


@pytest.mark.parametrize("reference", ["$actor", "$actor.email", "$actor.contact.email", "${actor.email}"])
def test_dollar_reference_status_agrees_in_plaintext_and_json(reference):
    text = json.dumps({"email": reference})
    for result in (classify_text(text), classify_structured(text)):
        assert len(result["matches"]) == 1
        row = result["matches"][0]
        assert (row["category"], row["subtype"]) == ("PII", "email")
        assert row["candidate_status"] == "identifier_reference"
        assert row["basis"] == "identifier_or_unquoted_value"
        assert row["value_status"] == "opaque"
        assert reference not in json.dumps(result)


@pytest.mark.parametrize("value", ["actor", "actor.email", "$actor.email", "${actor.email}"])
def test_existing_identifier_and_template_syntax_stays_supported(value):
    assert _REFERENCE.fullmatch(value)


@pytest.mark.parametrize("value", ["$actor.email()", "$actor['email']", "$actor[0]", "$actor..email", "$actor."])
def test_calls_brackets_and_incomplete_paths_are_not_identifier_syntax(value):
    assert not _REFERENCE.fullmatch(value)
    row = classify_structured(json.dumps({"email": value}))["matches"][0]
    assert row["candidate_status"] == "named_value_candidate"
    assert row["value_status"] == "unverified"


def test_quoted_bare_path_and_unmapped_reference_do_not_gain_value_provenance():
    for classifier in (classify_text, classify_structured):
        row = classifier('{"email":"actor.email"}')["matches"][0]
        assert row["candidate_status"] == "named_value_candidate"
        assert not classifier('{"ordinary":"$actor.email"}')["matches"]
    row = classify_text("Bearer actor.email")["matches"][0]
    assert row["candidate_status"] == "identifier_reference"
