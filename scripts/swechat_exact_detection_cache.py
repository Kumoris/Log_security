"""Memoize unchanged pure detector helpers; never alter their outputs or rules."""
import ast,copy,inspect
from functools import lru_cache

def install(detector, size=4096):
    from agentlog_unified import taxonomy
    original_types=detector._types;original_matches=taxonomy._matches
    @lru_cache(maxsize=8192)
    def cached_types(name):return frozenset(original_types(name))
    @lru_cache(maxsize=8192)
    def cached_matches(source,parent):return tuple(original_matches(source,parent=parent))
    def types(name):return set(cached_types(name))
    def matches(source,*,parent=None):return copy.deepcopy(list(cached_matches(source,parent)))
    detector._types=types;taxonomy._matches=matches
    originals={name:getattr(detector,name) for name in ['_go_entities','_csharp_entities','_lexical_entities']}
    # The current lexical helper accepts files for compatibility but never reads it.
    # Refuse to ignore that parameter if a future detector starts using it.
    body=ast.parse(inspect.getsource(originals['_lexical_entities']))
    if any(isinstance(n,ast.Name) and isinstance(n.ctx,ast.Load) and n.id=='files' for n in ast.walk(body)):
        raise RuntimeError('lexical_helper_now_depends_on_snapshot_context')
    caches={}
    for name,fn in originals.items():
        def factory(name,fn):
            @lru_cache(maxsize=size)
            def cached(path,source):
                return fn(path,source,{}) if name=='_lexical_entities' else fn(path,source)
            def wrapper(path,source,*args):return copy.deepcopy(cached(path,source))
            return cached,wrapper
        cached,wrapper=factory(name,fn);caches[name]=cached;setattr(detector,name,wrapper)
    def finish():
        stats={name:dict(fn.cache_info()._asdict()) for name,fn in caches.items()}
        stats['identifier_types_exact_cache']=dict(cached_types.cache_info()._asdict())
        stats['taxonomy_exact_input_cache']=dict(cached_matches.cache_info()._asdict())
        detector._types=original_types;taxonomy._matches=original_matches
        for name,fn in originals.items():setattr(detector,name,fn)
        return stats
    return finish
