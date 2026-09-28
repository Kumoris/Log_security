"""Share identical read-only repository gap lists across original trace calls.

The SWE-chat executor freezes the gap sequence before tracing and replaces each
case's coverage_gaps field with the existing aggregate export afterward. Neither
the tracer nor that exporter mutates the shared list or its records. This changes
storage aliasing only; filtering, order, duplicates and all result values remain.
"""
import inspect
import hashlib

ORIGINAL_TRACE_SHA256 = '0f41103b1613c46df2926249b7cc4566970c5b579ee62daeb48ac0b8577e0d3f'


class TraceGapStorage:
    def __init__(self, lineage, gaps):
        if not isinstance(gaps, tuple):
            raise TypeError('Freeze the gap sequence to a tuple before tracing')
        self.gaps = gaps
        self.views = {}
        self.requests = 0
        source = inspect.getsource(lineage.trace_logs)
        if hashlib.sha256(source.encode()).hexdigest() != ORIGINAL_TRACE_SHA256:
            raise RuntimeError('Original tracer changed; revalidate read-only gap contract')
        original = "repo_gaps=[g for g in all_gaps if g.get('repository_id')==rid or g.get('repository')==repo['repository_id']]"
        if source.count(original) != 1:
            raise RuntimeError('Original gap selection changed; revalidate storage adapter')
        # Keep the original predicate verbatim, including OR, order and duplicates.
        source = source.replace(original, "repo_gaps=_repository_gap_view(rid,repo['repository_id'])")
        scope = {**lineage.__dict__, '_repository_gap_view': self._view}
        exec(compile(source, inspect.getsourcefile(lineage.trace_logs) + '::<shared_gap_storage>', 'exec'), scope)
        self._trace = scope['trace_logs']

    def _view(self, rid, repository):
        self.requests += 1
        key = rid, repository
        if key not in self.views:
            self.views[key] = [g for g in self.gaps
                               if g.get('repository_id') == rid or g.get('repository') == repository]
        return self.views[key]

    def __call__(self, repositories, prs, mined_rows, events, snapshots, cutoff, days,
                 all_gaps, external_evidence=None):
        if all_gaps is not self.gaps:
            raise ValueError('Tracing must use the same frozen gap sequence')
        return self._trace(repositories, prs, mined_rows, events, snapshots, cutoff,
                           days, all_gaps, external_evidence)

    def statistics(self):
        return dict(repository_views=len(self.views), gap_view_requests=self.requests,
                    shared_gap_references=sum(len(v) for v in self.views.values()),
                    selection_predicate_unchanged=True, gap_order_and_duplicates_preserved=True,
                    algorithm_changes=False, use_contract='frozen input; lists read-only until export field replacement')
