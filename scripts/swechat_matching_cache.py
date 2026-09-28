"""Exact-input caches for immutable matching helpers; matching rules unchanged."""
import inspect
from functools import lru_cache


def install(analysis,matching):
    original_semantic=matching.semantic_code
    original_key=matching.entity_key
    original_analysis_key=analysis.entity_key
    expected="return stable_id(entity['path'], entity['symbol'], entity['identity'],\n                     entity.get('start_line'), entity.get('end_line'), statement_key(entity))"
    if expected not in inspect.getsource(original_key):
        raise RuntimeError('Revalidate matching key cache after formula change')
    cached_semantic=lru_cache(maxsize=32768)(original_semantic)
    @lru_cache(maxsize=65536)
    def cached_key(path,symbol,identity,start,end,statement):
        return matching.stable_id(path,symbol,identity,start,end,statement)
    def key(entity):
        return cached_key(entity['path'],entity['symbol'],entity['identity'],entity.get('start_line'),
                          entity.get('end_line'),matching.statement_key(entity))
    matching.semantic_code=cached_semantic
    matching.entity_key=key;analysis.entity_key=key
    def finish():
        stats=dict(semantic_code=cached_semantic.cache_info()._asdict(),entity_key=cached_key.cache_info()._asdict(),rules_changed=False)
        matching.semantic_code=original_semantic;matching.entity_key=original_key;analysis.entity_key=original_analysis_key
        return stats
    return finish


class CandidateIndex:
    """Pre-index the exact original before-key OR after-key predicate, in order."""
    def __init__(self,entity_key):
        self.entity_key=entity_key;self.rows=None;self.before={};self.after={}
    def __call__(self,rows,before,after):
        if rows is not self.rows:
            self.rows=rows;self.before={};self.after={}
            for i,row in enumerate(rows):
                self.before.setdefault(self.entity_key(row['before']),[]).append(i)
                if row['after']:self.after.setdefault(self.entity_key(row['after']),[]).append(i)
        selected=set(self.before.get(self.entity_key(before),())) if before else set()
        if after:selected.update(self.after.get(self.entity_key(after),()))
        return [rows[i] for i in sorted(selected)]
