"""Conservative log identity matching; formatting is not a behavior change."""
from __future__ import annotations

import ast
from collections import Counter
import textwrap

from .storage import canonical, stable_id


def semantic_code(source: str, python: bool) -> str:
    if python:
        try:
            return ast.dump(ast.parse(textwrap.dedent(source).strip()), include_attributes=False)
        except (SyntaxError, ValueError):
            pass
    return source.strip()


def statement_key(entity: dict) -> str:
    return entity.get('semantic_statement') or semantic_code(
        entity['statement'], entity.get('parser_status') == 'python_ast')


def behavior(entity: dict | None) -> str | None:
    if entity is None:
        return None
    python = entity.get('parser_status') == 'python_ast'
    dependencies = sorted((d.get('symbol', ''), semantic_code(d.get('code', ''), python),
                           d.get('kind', '')) for d in entity.get('dependencies', []))
    conditions = [semantic_code(t[10:], python) if t.startswith('condition:') else t
                  for t in entity.get('trigger_conditions', [])]
    return canonical([statement_key(entity), dependencies, conditions, entity.get('data_types')])


def match_entities(before: list[dict], after: list[dict], old_path: str | None = None,
                   new_path: str | None = None) -> list[dict]:
    """Only unique counterparts are supported; ordinals never resolve duplicates."""
    left, right, pairs = list(before), list(after), []
    def allowed(old, new):
        return old['symbol'] == new['symbol'] and (old['path'] == new['path'] or
                (old['path'] == old_path and new['path'] == new_path))
    for key, basis in ((statement_key, 'unique_semantic_statement'),
                       (lambda e: e.get('message_template'), 'unique_template'),
                       (lambda e: e['symbol'], 'unique_symbol_possible')):
        for old in list(left):
            old_template_count = sum(e['path'] == old['path'] and e['symbol'] == old['symbol']
                                     and e.get('message_template') == old.get('message_template') for e in before)
            new_template_count = sum(allowed(old, e) and e.get('message_template') == old.get('message_template') for e in after)
            if max(old_template_count, new_template_count) > 1 and old_template_count != new_template_count:
                # Even an identical survivor can be the other occurrence after
                # rewriting. A shrinking/growing duplicate group needs review.
                continue
            candidates = [new for new in right if allowed(old, new) and key(old) == key(new)]
            # Count against the original sides: greedy earlier matches must not
            # turn the remaining member of a duplicate group into certainty.
            old_count = sum(e['path'] == old['path'] and e['symbol'] == old['symbol']
                            and key(e) == key(old) for e in before)
            new_count = sum(allowed(old, e) and key(old) == key(e) for e in after)
            if len(candidates) != 1 or old_count != 1 or new_count != 1:
                continue
            new = candidates[0]
            left.remove(old)
            right.remove(new)
            kind = 'unchanged' if behavior(old) == behavior(new) else 'modified'
            if old['path'] != new['path']:
                kind = 'moved'
            pairs.append({'before': old, 'after': new, 'match_status': basis, 'change_kind': kind})
    pairs.extend({'before': old, 'after': None,
                  'match_status': 'ambiguous' if any(allowed(old, new) for new in right) else 'unmatched',
                  'change_kind': 'deleted'} for old in left)
    pairs.extend({'before': None, 'after': new,
                  'match_status': 'ambiguous' if any(allowed(old, new) for old in left) else 'unmatched',
                  'change_kind': 'added'} for new in right)
    return pairs


def match_cross_file(pairs: list[dict], changed_old: set[str], changed_new: set[str]) -> list[dict]:
    """Resolve only unique unchanged statements moved within this one commit."""
    removed = [p for p in pairs if p['before'] and p['after'] is None
               and p['before']['path'] in changed_old and p['match_status'] == 'unmatched']
    added = [p for p in pairs if p['after'] and p['before'] is None
             and p['after']['path'] in changed_new and p['match_status'] == 'unmatched']
    key = lambda e: (e['symbol'], statement_key(e), e.get('parser_status'))
    old_counts = Counter(key(p['before']) for p in removed)
    new_counts = Counter(key(p['after']) for p in added)
    result = list(pairs)
    for old_pair in removed:
        old = old_pair['before']
        matches = [p for p in added if key(p['after']) == key(old) and p['after']['path'] != old['path']]
        if old_counts[key(old)] == new_counts[key(old)] == len(matches) == 1:
            new_pair = matches[0]
            result.remove(old_pair)
            result.remove(new_pair)
            result.append({'before': old, 'after': new_pair['after'], 'change_kind': 'moved',
                           'match_status': 'unique_cross_file_semantic'})
        elif matches:
            old_pair['match_status'] = 'ambiguous'
            for pair in matches:
                pair['match_status'] = 'ambiguous'
    return result


def entity_key(entity: dict) -> str:
    return stable_id(entity['path'], entity['symbol'], entity['identity'],
                     entity.get('start_line'), entity.get('end_line'), statement_key(entity))


def resolve_match(before_snapshot: dict, after_snapshot: dict, before_key: str,
                  after_key: str | None, candidate_pairs: list[dict], reviewer: str) -> dict:
    """Validate a human-selected listed pair, without confirming privacy/authorship.

    ``candidate_pairs`` must be generated by the caller from its trusted stored
    candidates, not accepted from the review request. The caller persists the
    returned audit record; this function never changes source or candidate data.
    """
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise ValueError('A named human reviewer is required')
    if before_snapshot.get('repository_id') != after_snapshot.get('repository_id') or not before_snapshot.get('repository_id'):
        raise ValueError('Snapshots must belong to the same repository')
    if not before_snapshot.get('sha') or not after_snapshot.get('sha') or before_snapshot['sha'] == after_snapshot['sha']:
        raise ValueError('Distinct verified snapshot revisions are required')
    old = [e for e in before_snapshot['entities'] if entity_key(e) == before_key]
    new = [e for e in after_snapshot['entities'] if entity_key(e) == after_key] if after_key else []
    if len(old) != 1 or (after_key is not None and len(new) != 1):
        raise ValueError('Selected entities must exist uniquely in the supplied snapshots')
    listed = [p for p in candidate_pairs if p.get('before') and entity_key(p['before']) == before_key
              and (entity_key(p['after']) if p.get('after') else None) == after_key]
    if not listed:
        raise ValueError('Selected pair is not among the stored candidates')
    return {'before': old[0], 'after': new[0] if new else None,
            'match_status': 'human_confirmed_pair', 'change_kind': 'deleted' if not new else 'modified',
            'match_review': {'reviewer': reviewer.strip(), 'before_snapshot_sha': before_snapshot['sha'],
                             'after_snapshot_sha': after_snapshot['sha'], 'before_key': before_key,
                             'after_key': after_key, 'scope': 'entity_pair_only'}}
