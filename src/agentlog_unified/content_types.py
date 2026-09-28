"""Bounded plaintext type candidates, independent of application-log analysis.

Only offsets and finite labels leave this module. A matching value *shape* is
not a real credential, personal record, or confirmed disclosure. In particular,
the identifier taxonomy is applied only to explicit assignment keys, not prose.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

from .storage import SECRET_PATTERNS
from .taxonomy import CARRIERS, RULES, TAXONOMY_VERSION, _matches, taxonomy_catalog

CONTENT_DETECTOR_VERSION = "1.2.0"
MAX_SOURCE_CHARS = 1024 * 1024

# Reuse the public redactor's shape families, with finite token lengths and
# boundaries so a long nonmatching cell cannot cause unbounded backtracking.
_TOKEN = re.compile(SECRET_PATTERNS[0][0].replace("{20,}", "{20,256}") + r"(?![A-Za-z0-9_-])")
_JWT = re.compile(SECRET_PATTERNS[1][0].replace("{10,}", "{10,1024}") + r"(?![A-Za-z0-9_-])")
_BEARER = re.compile(SECRET_PATTERNS[2][0].replace(r"\s+", r"[ \t]{1,8}").replace(
    "[A-Za-z0-9._~+/=-]+", "[A-Za-z0-9._~+/=-]{1,2048}(?![A-Za-z0-9._~+/=-])"))
_EMAIL = re.compile(SECRET_PATTERNS[3][0].replace(r"\b[A-Z0-9._%+-]+", r"(?<![A-Z0-9._%+-])[A-Z0-9._%+-]{1,64}").replace(
    "[A-Z0-9.-]+", "[A-Z0-9.-]{1,253}").replace(r"[A-Z]{2,}\b", r"[A-Z]{2,63}(?![A-Z0-9.-])"))
_USERINFO = re.compile(SECRET_PATTERNS[4][0].replace("[a-z0-9+.-]*", "[a-z0-9+.-]{0,31}").replace(
    r"[^\s/:]+", r"[^\s/:]{1,256}").replace(r"[^\s/@]+", r"[^\s/@]{1,256}"))
_IPV4 = re.compile(r"(?<![\d.])" + SECRET_PATTERNS[8][0] + r"(?![\d.])")
_PEM_KINDS = ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY",
              "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY")
_NAMED = re.compile(
    r'''(?<![\w./-])(?P<quote>["']?)(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,95})(?P=quote)'''
    r'''[ \t]{0,16}[:=][ \t]{0,16}(?P<value>"(?:[^"\\\n]|\\.){0,4096}"|'''
    r"'(?:[^'\\\n]|\\.){0,4096}'|[^\s,;\"']{1,256})"
)
_UNKNOWN_KEY = re.compile(r"(?i)^(?:sensitive|personal|pii|confidential|private)(?:_?(?:data|value|info|information))?$")
_REFERENCE = re.compile(r"(?:\$?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*|\$\{[^\n]{1,256}\})$")
_TEMPLATE = re.compile(r"\{(?:\{|[A-Za-z_][\w.]*|\d*)\}|%[sdv]")
_EXAMPLE_WORD = re.compile(
    r"(?i)(?:^|[<>{}\s_:.-])(?:redacted|placeholder|dummy|synthetic|changeme|not[_ -]?valid|not[_ -]?real|"
    r"your[_ -](?:token|key|password)|example)(?:$|[<>{}\s_:.-])"
)
_EXAMPLE_DOMAIN = re.compile(r"(?i)@(?:[^@\s]*\.)?(?:example\.(?:com|org|net)|[^@\s]+\.(?:invalid|test))$")
_EXAMPLE_LINE = re.compile(r"(?i)^\s*(?:example|synthetic|fixture|dummy)[ \t]*[:=]")


def _example(text: str, start: int, end: int) -> bool:
    value = text[start:end].strip("\"'")
    if (re.fullmatch(r"[xX*]{3,}", value) or _EXAMPLE_WORD.search(value)
            or _EXAMPLE_DOMAIN.search(value)):
        return True
    line_start = max(text.rfind("\n", max(0, start - 256), start) + 1, start - 256)
    return bool(_EXAMPLE_LINE.match(text[line_start:start]))


def _record(text: str, start: int, end: int, category: str | None, subtype: str | None,
            rule: str, basis: str, status: str, value_status: str = "unverified") -> dict:
    if _example(text, start, end):
        status, value_status = "placeholder_or_example", "placeholder_or_example"
    return {"start": start, "end": end, "category": category, "subtype": subtype,
            "rule": rule, "basis": basis, "confidence": "low",
            "value_status": value_status, "candidate_status": status}


def _literal_candidates(text: str) -> Iterator[dict]:
    for match in _TOKEN.finditer(text):
        subtype = ("api_key" if match[0].startswith("sk-") else
                   "credential_bundle" if match[0].startswith("AKIA") else "access_token")
        yield _record(text, *match.span(), "AUTH", subtype, "credential_prefix_shape", "literal_shape", "literal_candidate")
    for regex, category, subtype, rule in (
        (_JWT, "AUTH", "access_token", "compact_jwt_shape"),
        (_BEARER, "AUTH", "authorization_header", "bearer_scheme_shape"),
        (_EMAIL, "PII", "email", "email_shape"),
        (_USERINFO, "AUTH", "credential_bundle", "url_userinfo_shape"),
    ):
        for match in regex.finditer(text):
            if regex is _EMAIL and any(
                userinfo.start() < match.start() < userinfo.end() < match.end()
                for userinfo in _USERINFO.finditer(text, max(0, match.start() - 550), match.end())
            ):
                continue  # URL password@host is not an independently observed email.
            basis, status, value_status = "literal_shape", "literal_candidate", "unverified"
            if regex is _BEARER:
                token = match[0].split(None, 1)[1]
                # A bearer scheme followed only by an identifier has no value
                # evidence beyond its scheme. Keep the ambiguity visible.
                if _REFERENCE.fullmatch(token):
                    basis, status, value_status = "identifier_or_unquoted_value", "identifier_reference", "opaque"
            yield _record(text, *match.span(), category, subtype, rule, basis, status, value_status)
    for match in _IPV4.finditer(text):
        try:
            ipaddress.IPv4Address(match[0])  # Syntax only; never a network lookup.
        except ValueError:
            continue
        yield _record(text, *match.span(), "QID", "network_identifier", "ipv4_shape", "literal_shape", "literal_candidate")
    # Monotonic delimiter searches avoid regex retries over incomplete PEM
    # envelopes. Only these six explicit wrappers are supported; no key parsing.
    for kind in _PEM_KINDS:
        opening, closing = f"-----BEGIN {kind}-----", f"-----END {kind}-----"
        cursor = 0
        while (start := text.find(opening, cursor)) >= 0:
            end = text.find(closing, start + len(opening))
            if end < 0:
                break
            cursor = end + len(closing)
            yield _record(text, start, cursor, "AUTH", "private_key", "private_key_envelope_shape", "literal_shape", "literal_candidate")


def _named_candidates(text: str) -> Iterator[dict]:
    for match in _NAMED.finditer(text):
        key, raw = match["key"], match["value"]
        rows = _matches(key)
        if not rows and not _UNKNOWN_KEY.fullmatch(key):
            continue  # Generic assignments are covered by the caller's unknown cell audit.
        start, end = match.span("value")
        quoted = len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]
        value = raw[1:-1] if quoted else raw.rstrip("}])")
        if quoted:
            start, end = start + 1, end - 1
        else:
            end = start + len(value)
        if end <= start:
            continue
        reference = bool((not quoted and _REFERENCE.fullmatch(value))
                         or value.startswith(("${", "$", "{", "[")) or _TEMPLATE.search(value))
        for row in rows or [(None, None, None, None, None)]:
            carrier = row[4] in CARRIERS
            status = ("identifier_reference" if reference else "carrier_candidate" if carrier else
                      "named_value_candidate" if rows else "unknown_named_value")
            basis = "identifier_or_unquoted_value" if reference else "named_carrier_hint" if carrier else "named_value_hint"
            yield _record(text, start, end, row[0], row[1], "named_field_taxonomy" if rows else "unclassified_sensitive_field",
                          basis, status, "opaque" if reference or carrier or not rows else "unverified")


def classify_text(text: str, *, max_matches: int = 1000) -> dict:
    """Return finite candidates with safe labels and half-open character spans.

    An empty result is not a safe/complete negative. The caller must retain an
    unknown-text queue and audit truncation. Results are selected in documented
    rule-family order, then sorted by span; capped results are not a random or
    representative sample. No values, excerpts, names or value hashes are returned.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if isinstance(max_matches, bool) or not isinstance(max_matches, int) or max_matches < 0:
        raise ValueError("max_matches must be a nonnegative integer")
    if len(text) > MAX_SOURCE_CHARS:
        raise ValueError("text exceeds the documented character bound; caller must truncate and audit")
    matches: dict[tuple, dict] = {}
    truncated = False
    for candidates in (_literal_candidates(text), _named_candidates(text)):
        for candidate in candidates:
            identity = (candidate["start"], candidate["end"], candidate["category"], candidate["subtype"])
            if identity in matches:
                continue
            if len(matches) >= max_matches:
                truncated = True
                break
            matches[identity] = candidate
        if truncated:
            break
    return {"matches": sorted(matches.values(), key=lambda row: (row["start"], row["end"], row["category"] or "", row["subtype"] or "")),
            "truncated": truncated}


def detector_catalog() -> dict:
    literal = {("AUTH", name) for name in ("access_token", "api_key", "credential_bundle", "authorization_header", "private_key")}
    literal |= {("PII", "email"), ("QID", "network_identifier")}
    catalog = taxonomy_catalog()
    rows = []
    named = {(row[0], row[1]): row[4] in CARRIERS for row in RULES}
    for category in catalog["categories"]:
        for subtype in category["subtypes"]:
            key = (category["category"], subtype["subtype"])
            rows.append({"category": key[0], "subtype": key[1], "literal_shape_subset": key in literal,
                         "named_hint_available": key in named, "carrier_hint": named.get(key, False),
                         "context_or_review_required": True})
    return {"content_detector_version": CONTENT_DETECTOR_VERSION, "taxonomy_version": TAXONOMY_VERSION,
            "evidence_scope": "dataset_text", "taxonomy_subtype_count": len(rows), "subtypes": rows,
            "literal_shape_subtype_count": len(literal), "named_hint_subtype_count": len(named),
            "max_source_chars": MAX_SOURCE_CHARS, "default_max_matches": 1000,
            "offset_unit": "unicode_characters_half_open", "match_selection": "rule_family_order_then_span_sort",
            "rule_family_order": ["credential_prefix", "jwt", "bearer", "email", "url_userinfo", "ipv4", "private_key_envelope", "named_field"],
            "candidate_statuses": ["literal_candidate", "named_value_candidate", "identifier_reference", "carrier_candidate", "placeholder_or_example", "unknown_named_value"],
            "limitations": [
                "All records are low-confidence static candidates requiring review; no real-value, ownership, liveness, or disclosure verification.",
                f"{len(literal)} subtypes have limited literal shapes; {len(named)} have identifier-key hints. The {len(rows)}-subtype taxonomy is not fully detectable.",
                "Named hints do not establish value type; bare identifiers and templates remain opaque; descriptive keywords alone produce no value candidate.",
                "Example/placeholder syntax is retained as a candidate status, never proof that a value is harmless or synthetic.",
                "Generic assignments and unmatched free text require the caller's unknown queue, including unknown portions of partially matched cells.",
                "Finite token/field lengths, six PEM wrappers, IPv4 only; no phone/name/address/medical semantics, arbitrary encoding, or full structured-text parsing.",
                "AKIA format is an access-key identifier, not a secret by itself; bearer scheme and URL userinfo do not prove active authentication.",
                "IP shape does not establish a person link; credential-looking strings, emails and IPs in code/prose/examples remain unverified.",
                "Only character offsets and finite labels are returned; no original text, values, names, or value hashes.",
            ]}
