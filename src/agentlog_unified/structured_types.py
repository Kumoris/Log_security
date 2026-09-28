"""Finite JSON structure hints, independent of the frozen plaintext classifier.

Only coordinates and finite labels leave this module. Decoded leaf offsets are
not offsets into the original cell. Unknown nodes remain semantically pending.
"""
from __future__ import annotations

import json
import re

from . import content_types
from .taxonomy import CARRIERS, TAXONOMY_VERSION, _matches

STRUCTURED_DETECTOR_VERSION = '1.1.0'
MAX_SOURCE_CHARS = content_types.MAX_SOURCE_CHARS
MAX_DEPTH = 256
MAX_DECODE_LAYERS = 2
MAX_LITERAL_CHARS = 65536
MAX_KEY_CHARS = 256
NODE_KINDS = {'object', 'array', 'string', 'number', 'boolean', 'null'}
DOCUMENT_STATUSES = {'parsed_with_semantic_gaps', 'invalid_json', 'partial'}
STATUSES = DOCUMENT_STATUSES | {'not_applicable'}
MATCH_FIELDS = {'document_index', 'node_path', 'node_kind', 'category', 'subtype',
                'rule', 'basis', 'candidate_status', 'value_status', 'confidence',
                'decoded_start', 'decoded_end'}
DOCUMENT_FIELDS = {'document_index', 'format', 'source_start', 'source_end', 'status'}
GAP_FIELDS = {'document_index', 'node_path', 'reason'}
GAP_REASONS = {'source_size_budget', 'document_budget', 'depth_budget', 'node_budget',
               'match_budget', 'decode_layer_budget', 'string_literal_size_budget',
               'key_size_budget', 'invalid_json', 'non_finite_json',
               'parser_recursion_limit', 'parser_value_limit',
               'unclosed_json_fence', 'invalid_encoded_json'}
COUNT_FIELDS = {'source_characters', 'source_characters_considered', 'documents_detected',
                'documents_selected', 'documents_parsed', 'documents_invalid',
                'nodes_visited', 'object_nodes', 'array_nodes', 'string_nodes',
                'number_nodes', 'boolean_nodes', 'null_nodes', 'keyed_nodes',
                'empty_string_nodes', 'whitespace_string_nodes', 'empty_object_nodes', 'empty_array_nodes',
                'unmapped_keys', 'duplicate_keys', 'unsupported_nodes', 'unknown_nodes',
                'encoded_json_attempts', 'encoded_json_parsed', 'encoded_json_invalid',
                'candidate_nodes', 'match_budget_nodes', 'matches_emitted', 'gap_records',
                'ignored_fences'}
MATCH_LABELS = {
    'node_kind': NODE_KINDS,
    'rule': {'credential_prefix_shape', 'compact_jwt_shape', 'bearer_scheme_shape',
             'email_shape', 'url_userinfo_shape', 'ipv4_shape',
             'private_key_envelope_shape', 'json_key_taxonomy'},
    'basis': {'literal_shape', 'identifier_or_unquoted_value', 'json_key_hint',
              'json_carrier_hint', 'json_parent_key_hint'},
    'candidate_status': {'literal_candidate', 'named_value_candidate',
                         'identifier_reference', 'carrier_candidate', 'placeholder_or_example'},
    'value_status': {'unverified', 'opaque', 'placeholder_or_example'},
    'confidence': {'low'},
}
_NUMBER_SYNTAX = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z')
_FENCE = re.compile(r'^[ \t]{0,3}(`{3,}|~{3,})([^\r\n]*)\r?\n?\Z')


class _Object(list):
    """Ordered pairs distinguish objects from arrays and preserve duplicate keys."""


class _Number:
    """A numeric kind marker; classification does not need numeric values."""


_NUMBER = _Number()


class _NonFinite(ValueError):
    pass


def _reject_constant(_):
    raise _NonFinite()


def _parse(raw, max_depth):
    # Inspect nesting without decoding strings or allocating a recursive tree.
    depth = 0; quoted = escaped = False
    for char in raw:
        if quoted:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in '[{':
            depth += 1
            if depth > max_depth + 1: return None, 'depth_budget'
        elif char in ']}': depth -= 1
    try:
        return json.loads(raw, object_pairs_hook=_Object, parse_constant=_reject_constant,
                          parse_int=lambda _: _NUMBER, parse_float=lambda _: _NUMBER), None
    except _NonFinite:
        return None, 'non_finite_json'
    except json.JSONDecodeError:
        return None, 'invalid_json'
    except RecursionError:
        return None, 'parser_recursion_limit'
    except ValueError:
        return None, 'parser_value_limit'


def _kind(value):
    if isinstance(value, _Object): return 'object'
    if isinstance(value, list): return 'array'
    if isinstance(value, str): return 'string'
    if isinstance(value, _Number): return 'number'
    if isinstance(value, bool): return 'boolean'
    return 'null'


def _documents(text, counts):
    stripped = text.strip()
    if stripped and (stripped[0] in '[{"' or stripped in {'true', 'false', 'null', 'NaN', 'Infinity', '-Infinity'} or _NUMBER_SYNTAX.fullmatch(stripped)):
        start = len(text) - len(text.lstrip())
        yield 'whole_json', start, start + len(stripped), stripped, None
        # A failed whole-document candidate (e.g. an issue title beginning '[')
        # must not hide a later explicit JSON fence. A valid JSON document cannot
        # contain a standalone physical fence line outside a quoted string.
    if '```' not in text and '~~~' not in text:
        return  # Syntax-only fast path; no content/key-based prefilter.
    active = None; offset = 0
    for line in text.splitlines(keepends=True):
        match = _FENCE.fullmatch(line)
        if active is None:
            if match:
                marker, info = match.groups()
                # A backtick in a backtick fence's info is not a fence opener.
                if marker[0] == '`' and '`' in info:
                    offset += len(line); continue
                selected = info.strip().lower() == 'json'
                active = (marker, selected, offset, offset + len(line))
                if not selected: counts['ignored_fences'] += 1
        elif match:
            marker, info = match.groups()
            if marker[0] == active[0][0] and len(marker) >= len(active[0]) and not info.strip():
                if active[1]:
                    yield 'fenced_json', active[2], offset + len(line), text[active[3]:offset], None
                active = None
        offset += len(line)
    if active and active[1]:
        yield 'fenced_json', active[2], len(text), None, 'unclosed_json_fence'


def _children(value, path, depth, layers, owner_name):
    if isinstance(value, _Object):
        for ordinal, (name, child) in enumerate(value):
            yield child, path + [ordinal], depth + 1, name, layers, owner_name
    elif isinstance(value, list):
        for ordinal, child in enumerate(value):
            yield child, path + [ordinal], depth + 1, None, layers, None


def _key_candidates(value, kind, rows, *, decoded_container=False, decoded_empty=False):
    if not rows or kind in {'boolean', 'null'}: return
    if kind in {'object', 'array', 'string'} and not value: return
    if kind == 'string' and not value.strip(): return
    if decoded_empty: return
    for category, subtype, _, _, legacy in rows:
        carrier = legacy in CARRIERS
        if (kind in {'object', 'array'} or decoded_container) and not carrier: continue
        start = end = None
        status = 'carrier_candidate' if carrier else 'named_value_candidate'
        basis = 'json_carrier_hint' if carrier else 'json_key_hint'
        value_status = 'opaque' if carrier else 'unverified'
        if kind == 'string' and not decoded_container:
            if not value: continue
            start, end = 0, len(value)
            if content_types._example(value, start, end):
                status = value_status = 'placeholder_or_example'
            elif (value.startswith('$') and content_types._REFERENCE.fullmatch(value)) or content_types._TEMPLATE.search(value):
                status, basis, value_status = 'identifier_reference', 'identifier_or_unquoted_value', 'opaque'
        yield {'category': category, 'subtype': subtype, 'rule': 'json_key_taxonomy',
               'basis': basis, 'candidate_status': status, 'value_status': value_status,
               'confidence': 'low', 'decoded_start': start, 'decoded_end': end}


def classify_structured(text, *, max_source_chars=1048576, max_documents=128,
                        max_depth=32, max_nodes=10000, max_decode_layers=2,
                        max_matches=1000):
    """Classify strict JSON nodes; no original values, names or hashes returned."""
    if not isinstance(text, str): raise TypeError('text must be a string')
    budgets = {'max_source_chars': max_source_chars, 'max_documents': max_documents,
               'max_depth': max_depth, 'max_nodes': max_nodes,
               'max_decode_layers': max_decode_layers, 'max_matches': max_matches}
    if any(type(v) is not int or v < 0 for v in budgets.values()):
        raise ValueError('Structured budgets must be nonnegative integers')
    if not 1 <= max_source_chars <= MAX_SOURCE_CHARS:
        raise ValueError('max_source_chars must be between 1 and 1048576')
    if max_decode_layers > MAX_DECODE_LAYERS or max_depth > MAX_DEPTH:
        raise ValueError('Maximum decode layers is 2 and maximum tree depth is 256')
    counts = dict.fromkeys(COUNT_FIELDS, 0); counts['source_characters'] = len(text)
    matches = []; documents = []; gaps = []; partial = False

    def gap(document_index, path, reason):
        nonlocal partial
        gaps.append({'document_index': document_index, 'node_path': list(path), 'reason': reason})
        counts['gap_records'] += 1; partial = True

    if len(text) > max_source_chars:
        gap(None, [], 'source_size_budget')
        return {'matches': [], 'documents': [], 'gaps': gaps, 'counts': counts, 'status': 'partial'}
    counts['source_characters_considered'] = len(text)
    document_budget_reported = False
    for format_name, start, end, raw, discovery_error in _documents(text, counts):
        counts['documents_detected'] += 1
        if len(documents) >= max_documents:
            if not document_budget_reported:
                gap(None, [], 'document_budget'); document_budget_reported = True
            continue
        index = len(documents)
        document = {'document_index': index, 'format': format_name,
                    'source_start': start, 'source_end': end,
                    'status': 'parsed_with_semantic_gaps'}
        documents.append(document); counts['documents_selected'] += 1
        gap_before = len(gaps)
        if discovery_error:
            gap(index, [], discovery_error); document['status'] = 'partial'; continue
        if counts['nodes_visited'] >= max_nodes:
            gap(index, [], 'node_budget'); document['status'] = 'partial'; continue
        value, error = _parse(raw, max_depth)
        if error:
            gap(index, [], error)
            document['status'] = 'invalid_json' if error in {'invalid_json', 'non_finite_json'} else 'partial'
            counts['documents_invalid'] += int(document['status'] == 'invalid_json')
            continue
        counts['documents_parsed'] += 1
        stack = [iter([(value, [], 0, None, 0, None)])]
        while stack:
            try: value, path, depth, name, layers, parent_name = next(stack[-1])
            except StopIteration:
                stack.pop(); continue
            if counts['nodes_visited'] >= max_nodes:
                gap(index, path, 'node_budget'); break
            if depth > max_depth:
                gap(index, path, 'depth_budget'); continue
            kind = _kind(value); counts['nodes_visited'] += 1; counts[kind + '_nodes'] += 1
            if kind in {'object', 'array', 'string'} and not value:
                counts['empty_' + kind + '_nodes'] += 1
            elif kind == 'string' and not value.strip():
                counts['whitespace_string_nodes'] += 1
            rows = []; parent_labels = set()
            if name is not None:
                counts['keyed_nodes'] += 1
                if len(name) > MAX_KEY_CHARS:
                    gap(index, path, 'key_size_budget')
                else:
                    rows = _matches(name)
                    if parent_name is not None and len(parent_name) <= MAX_KEY_CHARS:
                        leaf_labels = {(r[0], r[1]) for r in rows}
                        rows = _matches(name, parent=parent_name)
                        parent_labels = {(r[0], r[1]) for r in rows} - leaf_labels
                if not rows: counts['unmapped_keys'] += 1
            if kind == 'object':
                counts['duplicate_keys'] += len(value) - len({pair[0] for pair in value})
            if kind in {'boolean', 'null'} or (kind in {'object', 'array'} and any(r[4] not in CARRIERS for r in rows)):
                counts['unsupported_nodes'] += 1
            decoded = None; decoded_ok = False
            if kind == 'string' and value.strip() and value.lstrip()[0] in '[{"':
                if layers >= max_decode_layers:
                    gap(index, path, 'decode_layer_budget')
                elif depth >= max_depth:
                    gap(index, path, 'depth_budget')
                else:
                    counts['encoded_json_attempts'] += 1
                    decoded, error = _parse(value, max_depth - depth - 1)
                    if error:
                        counts['encoded_json_invalid'] += 1
                        gap(index, path, 'invalid_encoded_json' if error == 'invalid_json' else error)
                    else:
                        decoded_ok = True; counts['encoded_json_parsed'] += 1
            decoded_container = decoded_ok and _kind(decoded) in {'object', 'array'}
            if decoded_container and any(r[4] not in CARRIERS for r in rows):
                counts['unsupported_nodes'] += 1
            candidates = {}
            remaining = max_matches - len(matches)
            overflow = False

            def remember(candidate):
                nonlocal overflow
                identity = candidate['decoded_start'], candidate['decoded_end'], candidate['category'], candidate['subtype']
                candidates.setdefault(identity, candidate)
                if len(candidates) > remaining: overflow = True

            if kind == 'string' and not decoded_ok:
                if len(value) > MAX_LITERAL_CHARS:
                    gap(index, path, 'string_literal_size_budget')
                else:
                    for candidate in content_types._literal_candidates(value):
                        candidate = dict(candidate)
                        candidate['decoded_start'] = candidate.pop('start')
                        candidate['decoded_end'] = candidate.pop('end')
                        remember(candidate)
                        if overflow: break
            if not overflow:
                for candidate in _key_candidates(value, kind, rows, decoded_container=decoded_container,
                                                 decoded_empty=decoded_container and not decoded):
                    if (candidate['category'], candidate['subtype']) in parent_labels:
                        candidate = {**candidate, 'basis': 'json_parent_key_hint'}
                    remember(candidate)
                    if overflow: break
            if candidates: counts['candidate_nodes'] += 1
            if overflow:
                gap(index, path, 'match_budget'); counts['match_budget_nodes'] += 1
            elif candidates:
                for candidate in candidates.values():
                    matches.append({'document_index': index, 'node_path': list(path), 'node_kind': kind, **candidate})
                counts['matches_emitted'] = len(matches)
            else: counts['unknown_nodes'] += 1
            if decoded_ok:
                stack.append(iter([(decoded, path + [-1], depth + 1, None, layers + 1, None)]))
            elif kind in {'object', 'array'}:
                stack.append(_children(value, path, depth, layers, name))
        if len(gaps) > gap_before: document['status'] = 'partial'
    if not documents:
        status = 'partial' if partial else 'not_applicable'
    elif all(d['status'] == 'invalid_json' for d in documents) and not any(g['reason'] not in {'invalid_json', 'non_finite_json'} for g in gaps):
        status = 'invalid_json'
    else:
        status = 'partial' if partial else 'parsed_with_semantic_gaps'
    return {'matches': matches, 'documents': documents, 'gaps': gaps, 'counts': counts, 'status': status}


def detector_catalog():
    return {'structured_detector_version': STRUCTURED_DETECTOR_VERSION,
            'taxonomy_version': TAXONOMY_VERSION,
            'formats': ['whole_json', 'fenced_json'],
            'selection': 'Whole-cell object/array/quoted-string or complete JSON scalar syntax; explicit standalone json fences. No key prefilter.',
            'document_offset_unit': 'original_cell_unicode_characters_half_open_envelope',
            'leaf_offset_unit': 'current_decoded_string_unicode_characters_half_open_not_original_cell',
            'node_path': 'Zero-based object-member or array ordinals; -1 is a JSON-string decode boundary.',
            'match_cap_policy': 'Atomic node: omit all node labels if its complete output exceeds remaining capacity; keep traversing with an explicit gap.',
            'max_literal_chars': MAX_LITERAL_CHARS, 'max_key_chars': MAX_KEY_CHARS,
            'max_source_chars': MAX_SOURCE_CHARS, 'max_depth': MAX_DEPTH,
            'max_decode_layers': MAX_DECODE_LAYERS,
            'limitations': ['Finite key hints and seven literal-shape subtype families, not complete sensitive-type detection.',
                            'Keys apply to their direct value; controlled ambiguous leaf fields may use one immediate object-parent name with a match touching the leaf.',
                            'Parent context resets across array-element and JSON-string decode boundaries, and never crosses intermediate object ancestors.',
                            'Unknown and unsupported nodes remain pending; generic id/name/repo fields gain no inferred personal meaning.',
                            'At most two additional JSON-string decode layers; no arbitrary base64, URL, HTML, JSON5 or language-code decoding.',
                            'Depth may reject a document before parsing; node and match caps do not establish safe negatives.',
                            'No original text, key names, numeric/string values, value hashes, credential checks or target execution.']}
