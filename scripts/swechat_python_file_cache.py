"""Version-pinned per-file Python caching with complete import-context keys.

Constructor indexing is path-local (its alias loop explicitly rejects other
paths). Entity evaluation reads other modules only through imported/function/model.
The key includes every resolved import (including unresolved/ambiguous imports)
and exact sources of the transitive import closure. Resolution is recomputed
against the entire parsed namespace, including suffix ambiguity. No changed selection or analysis rule.
AST/index objects are read-only after construction; per-snapshot outer containers
and all returned entity dictionaries are separate.
"""
import ast
import copy
import hashlib
import inspect
import textwrap
from collections import OrderedDict,defaultdict
from swechat_python_evaluation_cache import CLASS_SHA256,Dependencies


def install(detector,size=4096,*,accessed_imports=False):
    cls=detector.PythonSnapshot
    source=inspect.getsource(cls)
    if hashlib.sha256(source.encode()).hexdigest()!=CLASS_SHA256:
        raise RuntimeError('Revalidate Python per-file cache after parser changes')
    original_init,original_entities,original_imported=cls.__init__,cls.entities,cls.imported
    tree=ast.parse(source)
    method=next(n for n in tree.body[0].body if isinstance(n,ast.FunctionDef) and n.name=='entities')
    entity_source=textwrap.dedent(ast.get_source_segment(source,method))
    old='for path, tree in sorted(self.trees.items()):'
    if entity_source.count(old)!=1:raise RuntimeError('Entity iteration changed')
    entity_source=entity_source.replace(old,'for path, tree in ((requested_path, self.trees[requested_path]),):')
    entity_source=entity_source.replace('def entities(self)', 'def entities(self, requested_path)')
    entity_source=entity_source.replace('deps: list[dict] = []','deps: list[dict] = _SwechatDependencies()')
    scope={**detector.__dict__,'_SwechatDependencies':Dependencies}
    exec(compile(entity_source,inspect.getsourcefile(cls)+'::<per_file_entities>','exec'),scope)
    one_file_entities=scope['entities']
    def suffix_matches(snapshot,suffix):
        lookup=getattr(snapshot,'_swechat_suffix_paths',None)
        if lookup is None:
            lookup={}
            for path in snapshot.trees:
                for i,char in enumerate(path):
                    if char=='/':lookup.setdefault(path[i+1:],[]).append(path)
            snapshot._swechat_suffix_paths=lookup
        return lookup.get(suffix,())
    imported_source=textwrap.dedent(inspect.getsource(original_imported))
    expression='matches = [p for p in self.trees if p.endswith("/" + suffix)]'
    if imported_source.count(expression)!=1:raise RuntimeError('Import suffix predicate changed')
    imported_source=imported_source.replace(expression,'matches = _SuffixMatches(self,suffix)')
    import_scope={**detector.__dict__,'_SuffixMatches':suffix_matches}
    exec(compile(imported_source,inspect.getsourcefile(cls)+'::<exact_suffix_index>','exec'),import_scope)
    indexed_imported=import_scope['imported']
    indexes=OrderedDict();results=OrderedDict()
    stats={'index_hits':0,'index_misses':0,'entity_hits':0,'entity_misses':0,'import_hits':0,'access_validation_hits':0}
    attributes=('trees','parents','functions','classes','imports','assignments','mutations','logger_names','direct_imports')
    def init(self,files):
        original_init(self,{})
        self.files=files
        for path,source in sorted(files.items()):
            if not path.endswith('.py'):continue
            key=(path,source)
            if key in indexes:
                indexes.move_to_end(key);indexed=indexes[key];stats['index_hits']+=1
            else:
                indexed=cls.__new__(cls);original_init(indexed,{path:source})
                indexes[key]=indexed;stats['index_misses']+=1
                if len(indexes)>size:indexes.popitem(last=False)
            for attr in attributes:
                getattr(self,attr).update(getattr(indexed,attr))
            self.gaps.extend(indexed.gaps)
    def imported(self,path,callee):
        cache=getattr(self,'_swechat_import_lookup',None)
        if cache is None:cache=self._swechat_import_lookup={}
        key=(path,callee)
        if key in cache:
            stats['import_hits']+=1;result=cache[key]
        else:
            result=indexed_imported(self,path,callee);cache[key]=result
        reads=getattr(self,'_swechat_active_import_reads',None)
        if reads is not None:reads[key]=result
        return result
    def accessed_entities(self):
        # All cross-file PythonSnapshot reads enter through imported() in
        # function()/model()/sink(). The class digest pins that access boundary.
        # Record unsuccessful and ambiguous lookups too: a newly available module
        # or symbol must invalidate the old result. Returned target files are
        # tracked even when they are only rejected lookup candidates.
        hashes={p:hashlib.sha256(self.files[p].encode()).hexdigest() for p in self.trees}
        output=[]
        for path in sorted(self.trees):
            prior=results.get(path)
            if (prior and prior[0]==hashes[path]
                and all(hashes.get(p)==h for p,h in prior[2])
                and all(self.imported(p,callee)==resolved for (p,callee),resolved in prior[1])):
                results.move_to_end(path);stats['entity_hits']+=1;stats['access_validation_hits']+=1
                rows=prior[3]
            else:
                # Empty-binding value cache hits must not conceal import reads
                # performed for another root file. Per-file isolation retains
                # the cache's exact original evaluations within this file.
                self._swechat_empty_binding_values=OrderedDict()
                self._swechat_dependency_values=OrderedDict()
                self._swechat_active_import_reads={}
                try:
                    rows=one_file_entities(self,path)
                    reads=tuple(self._swechat_active_import_reads.items())
                finally:
                    self._swechat_active_import_reads=None
                touched={path}|{p for (p,callee),resolved in reads}|{resolved[0] for key,resolved in reads if resolved is not None}
                sources=tuple((p,hashes[p]) for p in sorted(touched))
                results[path]=(hashes[path],reads,sources,copy.deepcopy(rows))
                results.move_to_end(path);stats['entity_misses']+=1
                if len(results)>size:results.popitem(last=False)
            output.extend(copy.deepcopy(rows))
        return output
    def entities(self):
        # Recompute resolutions against all trees. Storing resolution outcomes
        # prevents unrelated new paths from invalidating every file cache entry.
        hashes={p:hashlib.sha256(self.files[p].encode()).hexdigest() for p in self.trees}
        resolutions={p:tuple((alias,self.imported(p,alias)) for alias in tuple(self.imports[p])) for p in self.trees}
        edges={p:{r[0] for alias,r in resolved if r is not None} for p,resolved in resolutions.items()}
        def closure(path):
            seen=set();pending=[path]
            while pending:
                p=pending.pop()
                if p in seen:continue
                seen.add(p);pending.extend(edges.get(p,()))
            return tuple((p,hashes[p],resolutions[p]) for p in sorted(seen))
        output=[]
        for path in sorted(self.trees):
            context=closure(path)
            key=(path,context)
            if key in results:
                results.move_to_end(key);rows=results[key];stats['entity_hits']+=1
            else:
                rows=one_file_entities(self,path);results[key]=copy.deepcopy(rows);stats['entity_misses']+=1
                if len(results)>size:results.popitem(last=False)
            output.extend(copy.deepcopy(rows))
        return output
    cls.__init__=init;cls.entities=accessed_entities if accessed_imports else entities;cls.imported=imported
    def finish():
        cls.__init__=original_init;cls.entities=original_entities;cls.imported=original_imported
        return dict(stats,adapter='version_pinned_file_index_and_transitive_import_context_cache',
                    size=size,rules_changed=False,namespace_resolution_includes_suffix_ambiguity=True,exact_suffix_index=True,
                    accessed_imports_only=accessed_imports,empty_binding_cache_isolated_per_file=accessed_imports)
    return finish
