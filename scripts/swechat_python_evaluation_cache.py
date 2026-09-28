"""Cache pure repeated evaluations in the version-pinned original Python parser.

Only empty-bound-environment evaluations are cached. Returned Values and evidence
dicts are copied. Dependency accumulation preserves exactly the final original
ordered-key/last-value reduction, which no evaluation decision reads.
"""
import ast
import copy
import hashlib
import inspect
import textwrap
from collections import OrderedDict

CLASS_SHA256='74127720e8f7618e7b8a4a0a7bf9ec75fe5a19e9d6ab8714222747554cb6534e'


class Dependencies:
    def __init__(self):self.rows={}
    def append(self,row):
        self.rows[(row['path'],row['symbol'],row['start_line'],row['end_line'],row['kind'])]=row
    def extend(self,rows):
        for row in rows:self.append(row)
    def __iter__(self):return iter(self.rows.values())


def install(detector,size=1024):
    cls=detector.PythonSnapshot
    if hashlib.sha256(inspect.getsource(cls).encode()).hexdigest()!=CLASS_SHA256:
        raise RuntimeError('Python parser changed; revalidate pure evaluation cache')
    original_value,original_dependency,original_entities=cls.value,cls.dependency,cls.entities
    stats={'value_cache_hits':0,'value_cache_misses':0,'dependency_cache_hits':0}
    def dependency(self,path,node,kind,symbol=None):
        cache=getattr(self,'_swechat_dependency_values',None)
        if cache is None:cache=self._swechat_dependency_values=OrderedDict()
        key=(path,node,kind,symbol)
        if key in cache:
            cache.move_to_end(key);stats['dependency_cache_hits']+=1
            return dict(cache[key])
        result=original_dependency(self,path,node,kind,symbol)
        cache[key]=dict(result)
        if len(cache)>4096:cache.popitem(last=False)
        return result
    def value(self,path,node,symbol,line,deps,bindings=None,calls=0,depth=0):
        if bindings:
            return original_value(self,path,node,symbol,line,deps,bindings,calls,depth)
        cache=getattr(self,'_swechat_empty_binding_values',None)
        if cache is None:cache=self._swechat_empty_binding_values=OrderedDict()
        # Synthetic Names generated for previous conditional values have no
        # source position; the original evaluator reads their identifier only.
        node_key=('synthetic_name',node.id) if isinstance(node,ast.Name) and not hasattr(node,'lineno') else node
        key=(path,node_key,symbol,line,calls,depth)
        if key in cache:
            cache.move_to_end(key);stats['value_cache_hits']+=1
            result,evidence=cache[key]
            deps.extend(dict(row) for row in evidence)
            return copy.deepcopy(result)
        stats['value_cache_misses']+=1
        evidence=Dependencies()
        result=original_value(self,path,node,symbol,line,evidence,bindings,calls,depth)
        saved=tuple(dict(row) for row in evidence)
        cache[key]=(copy.deepcopy(result),saved)
        if len(cache)>size:cache.popitem(last=False)
        deps.extend(dict(row) for row in saved)
        return result
    source=textwrap.dedent(inspect.getsource(original_entities))
    old='deps: list[dict] = []'
    if source.count(old)!=1:raise RuntimeError('Dependency accumulator changed')
    source=source.replace(old,'deps: list[dict] = _SwechatDependencies()')
    scope={**detector.__dict__,'_SwechatDependencies':Dependencies}
    exec(compile(source,inspect.getsourcefile(original_entities)+'::<pure_evaluation_cache>','exec'),scope)
    cls.value=value;cls.dependency=dependency;cls.entities=scope['entities']
    def finish():
        cls.value=original_value;cls.dependency=original_dependency;cls.entities=original_entities
        return dict(stats,adapter='version_pinned_empty_binding_evaluation_cache',
                    rules_changed=False,value_cache_entries_per_snapshot=size)
    return finish
