"""Index an existing exact path/scope predicate; no detection rules change."""
import inspect
from collections import defaultdict


def _items(snapshot, path, scopes):
    index = getattr(snapshot, '_swechat_mutation_lookup', None)
    if index is None:
        index = defaultdict(list)
        for order, (key, value) in enumerate(snapshot.mutations.items()):
            index[key[:2]].append((order, key, value))
        snapshot._swechat_mutation_lookup = index
    selected = [row for scope in set(scopes) for row in index.get((path, scope), ())]
    return [(key, value) for _, key, value in sorted(selected, key=lambda row: row[0])]


def install(detector):
    cls = detector.PythonSnapshot
    original = cls.apply_mutations
    source = inspect.getsource(original)
    import textwrap
    source = textwrap.dedent(source)
    old = 'for (event_path, scope, receiver), mutations in self.mutations.items():'
    if source.count(old) != 1:
        raise RuntimeError('python_mutation_loop_changed_revalidate_index')
    # The original rejection predicate remains in the compiled method as well.
    predicate = 'if event_path != path or scope not in {symbol, root_scope}:'
    if source.count(predicate) != 1:
        raise RuntimeError('python_mutation_predicate_changed_revalidate_index')
    source = source.replace(old, 'for (event_path, scope, receiver), mutations in _swechat_items(self, path, (symbol, root_scope)):')
    scope = {**detector.__dict__, '_swechat_items': _items}
    exec(compile(source, inspect.getsourcefile(original) + '::<exact_scope_index>', 'exec'), scope)
    cls.apply_mutations = scope['apply_mutations']

    def finish():
        cls.apply_mutations = original
        return dict(adapter='exact_mutation_path_scope_index', order_preserved=True,
                    evaluation_rules_changed=False)
    return finish
