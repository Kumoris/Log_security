"""Storage-only adapters for the original history detector.

The project matcher, event generation, gap transitions and tracer are unchanged.
Keep complete entity snapshots only where trace_logs reads them. Share immutable
gap-history prefixes instead of copying an ever-growing list at every commit.
"""
import inspect

class Changes:
    def __init__(self,parent=()):self.parent=parent;self.chunks=[]
    def extend(self,items):self.chunks.append(tuple(items))
    def __iter__(self):
        chain=[];node=self
        while isinstance(node,Changes):chain.append(node.chunks);node=node.parent
        yield from node
        for chunks in reversed(chain):
            for chunk in chunks:yield from chunk
    def __add__(self,items):return list(self)+list(items)

def integration_snapshots(mined,initials):
    initials=set(initials);masks={};integration={};fp=set(mined['first_parent_shas'])
    for row in mined['graph']:
        reachable=({row['sha']} if row['sha'] in initials else set())
        for p in row['parents']:reachable.update(masks.get(p,()))
        masks[row['sha']]=reachable
        if row['sha'] in fp:
            for origin in reachable:integration.setdefault(origin,row['sha'])
    return initials|set(integration.values())

def detect(analysis,repo,mined,config,initials):
    from swechat_matching_cache import CandidateIndex
    candidate_index=CandidateIndex(analysis.entity_key)
    keep=integration_snapshots(mined,initials)
    class Snapshots(dict):
        def __setitem__(self,sha,value):
            super().__setitem__(sha,value if sha in keep else {**value,'entities':[]})
    source=inspect.getsource(analysis.detect_history)
    substitutions={
        'gaps, events, snapshots, audit = [], [], {}, []':'gaps, events, snapshots, audit = [], [], _StoredSnapshots(), []',
        "'changes': list(state['changes'])":"'changes': _StoredChanges(state['changes'])",
        "for p in candidate_pairs if\n                    (before and entity_key": "for p in _IndexedCandidates(candidate_pairs,before,after) if\n                    (before and entity_key",
    }
    for old,new in substitutions.items():
        if source.count(old)!=1:raise RuntimeError('Original detector changed; storage adapter needs revalidation')
        source=source.replace(old,new)
    scope={**analysis.__dict__,'_StoredSnapshots':Snapshots,'_StoredChanges':Changes,'_IndexedCandidates':candidate_index}
    exec(compile(source,inspect.getsourcefile(analysis.detect_history)+'::<storage_adapter>','exec'),scope)
    result=scope['detect_history'](repo,mined,config)
    result['storage_adapter']={'retained_entity_snapshots':sorted(keep),'algorithm_changes':False,
        'shared_gap_prefixes':True,'manual_match_overrides':False,'exact_candidate_predicate_index':True}
    return result
