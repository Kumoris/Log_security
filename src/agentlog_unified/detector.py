"""Snapshot-only logging detection and bounded, non-executing static evidence.

The identifiers follow the workspace logguard/genguard.py source categories,
but detection deliberately precedes privacy assessment. No target is imported.
"""
from __future__ import annotations

import ast
import hashlib
import json
import posixpath
import re
from copy import deepcopy
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from pygments.lexers import CSharpLexer, GoLexer, JavaLexer, JavascriptLexer, TypeScriptLexer
from pygments.token import Comment, Error, Name, String

from .taxonomy import SENSITIVE_TYPES, annotate_entity, identifier_subject, identifier_types, matches_subject

LEVELS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "trace", "log"}
LANGUAGES = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript", ".jsx": "jsx", ".tsx": "tsx", ".go": "go", ".cs": "csharp", ".java": "java"}
# Reuses logguard's categories and aggregate exception, with word boundaries to
# avoid treating tokenizer/catalogue and password_enabled as credential values.
RULES = (
    (re.compile(r"(?:^|_)(?:password|passwd|pwd|secret|token|credentials?|jwt|cookie|authorization)(?:$|_)|(?:api|access|private|secret)_?key|(?:access|refresh|auth|session)_?token|client_?secret", re.I), "credential"),
    (re.compile(r"session_?id", re.I), "session_identifier"),
    (re.compile(r"(?:^|_)(?:email|phone|ssn|username|address|customer)(?:$|_)|(?:user|account|device|tenant)_?id", re.I), "personal_identifier"),
    (re.compile(r"(?:database_?url|connection_?string|dsn)", re.I), "connection_string"),
    (re.compile(r"(?:^|_)(?:request|response|payload|body|headers?|form|query|context|user|validator)(?:$|_)", re.I), "opaque_object"),
    (re.compile(r"(?:^|_)(?:config|environment|env)(?:$|_)", re.I), "internal_configuration"),
    (re.compile(r"(?:^|_)(?:prompt|completion|tool_output|retrieved|document|content)(?:$|_)", re.I), "content_visibility_unknown"),
)
SENSITIVE = {"credential", "session_identifier", "personal_identifier", "connection_string"} | SENSITIVE_TYPES
MASKED = re.compile(r"^(?:\*+|x{3,}|<redacted(?::[^>]*)?>|\[redacted\]|redacted|hidden|masked)?$", re.I)


def _types(name: str) -> set[str]:
    subject = identifier_subject(name)
    return {kind for regex, kind in RULES if matches_subject(regex, subject)} | identifier_types(name)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    if isinstance(node, ast.Call):
        return _name(node.func) + "()"
    return ""


@lru_cache(maxsize=4)
def _source_line_bytes(source: str) -> tuple[bytes, ...]:
    # AST columns are UTF-8 byte offsets; only CR/LF delimit parser lines.
    # A four-source cache avoids rescanning entire files for every dependency.
    return tuple(line for line in re.findall(rb"[^\r\n]*(?:\r\n|\r|\n|$)", source.encode("utf-8")) if line)


def _snippet(source: str, node: ast.AST) -> str:
    positions = [getattr(node, key, None) for key in ("lineno", "end_lineno", "col_offset", "end_col_offset")]
    if any(position is None for position in positions):
        return ""
    start, end, column, end_column = positions
    lines = _source_line_bytes(source)
    if start == end:
        return lines[start - 1][column:end_column].decode("utf-8")
    return b"".join((lines[start - 1][column:], *lines[start:end - 1], lines[end - 1][:end_column])).decode("utf-8")


@dataclass
class Value:
    types: set[str] = field(default_factory=set)
    evidence: list[dict] = field(default_factory=list)
    fields: dict[str, "Value"] | None = None
    known: bool = False
    sanitization: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    masked: bool = False
    boolean: bool = False


def _join(values: list[Value], *, fields: dict[str, Value] | None = None) -> Value:
    # Conditional mutations join the previous value with an updated value that
    # already contains it. Keep evidence as a stable set, not exponential copies.
    return Value(
        types=set().union(*(v.types for v in values)) if values else set(),
        evidence=list({json.dumps(e, sort_keys=True): e for v in values for e in v.evidence}.values()), fields=fields,
        known=all(v.known for v in values),
        sanitization=list(dict.fromkeys(s for v in values for s in v.sanitization)),
        gaps=list(dict.fromkeys(g for v in values for g in v.gaps)),
        boolean=bool(values) and all(v.boolean for v in values),
        masked=(bool(values) and all(v.masked for v in values)) or (not values and fields == {}),
    )


class PythonSnapshot:
    def __init__(self, files: dict[str, str]):
        self.files = dict(files)
        # ASTs and source strings belong to this historical snapshot only.
        self._dependency_cache: dict[tuple, dict] = {}
        self._dependency_records: dict[tuple, tuple] = {}
        self._value_cache: dict[tuple, tuple[Value, list[tuple]]] | None = None
        self.trees: dict[str, ast.Module] = {}
        self.parents: dict[str, dict[ast.AST, ast.AST]] = {}
        self.functions: dict[tuple[str, str], ast.AST] = {}
        self.classes: dict[tuple[str, str], ast.ClassDef] = {}
        self.imports: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)
        self.assignments: dict[tuple[str, str, str], list[ast.AST]] = defaultdict(list)
        self.mutations: dict[tuple[str, str, str], list[tuple[ast.AST, list[str | None], str]]] = defaultdict(list)
        self._mutations_by_scope: dict[tuple[str, str], list[tuple[str, list]]] = defaultdict(list)
        self.logger_names: dict[str, set[str]] = defaultdict(set)
        self.direct_imports: dict[str, dict[str, str]] = defaultdict(dict)
        self.gaps: list[dict] = []
        for path, source in sorted(files.items()):
            if not path.endswith(".py"):
                continue
            try:
                tree = ast.parse(source, filename=path)
            except (SyntaxError, ValueError, RecursionError) as exc:
                self.gaps.append({"path": path, "reason": "python_ast_parse_failed", "error_type": type(exc).__name__, "line": getattr(exc, "lineno", None)})
                continue
            self.trees[path] = tree
            self.parents[path] = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
            self.logger_names[path].update({"logging"})
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions[(path, self.symbol(path, node, include_self=True))] = node
                elif isinstance(node, ast.ClassDef):
                    self.classes[(path, node.name)] = node
                elif isinstance(node, ast.Import):
                    for item in node.names:
                        alias = item.asname or item.name.split(".")[0]
                        self.imports[path][alias] = (item.name, "")
                        if item.name in {"logging", "structlog"}:
                            self.logger_names[path].add(alias)
                elif isinstance(node, ast.ImportFrom):
                    module = "." * node.level + (node.module or "")
                    for item in node.names:
                        alias = item.asname or item.name
                        self.imports[path][alias] = (module, item.name)
                        if node.module in {"logging", "loguru", "structlog"}:
                            self.direct_imports[path][alias] = item.name
                            if item.name == "logger":
                                self.logger_names[path].add(alias)
                elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, (ast.Name, ast.Attribute)):
                            self.assignments[(path, self.symbol(path, node), _name(target))].append(node)
                        self._index_mutation(path, node, target, "set", require_field=True)
                elif isinstance(node, ast.AugAssign):
                    self._index_mutation(path, node, node.target, "augment")
                elif isinstance(node, ast.Delete):
                    for target in node.targets:
                        self._index_mutation(path, node, target, "delete")
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    method = node.func.attr
                    if method in {"update", "setdefault", "pop", "clear", "popitem", "append", "extend", "insert", "add", "remove", "discard"} or isinstance(self.parents[path].get(node), ast.Expr):
                        self._index_mutation(path, node, node.func.value, "call:" + method)
                if isinstance(node, ast.Call) and _name(node.func).rsplit(".", 1)[-1] not in LEVELS | {"len", "bool", "str", "repr", "vars", "asdict", "dict", "print", "dumps", "update", "setdefault", "get", "getLogger", "get_logger", "LoggerAdapter"} and self.direct_imports[path].get(_name(node.func)) not in LEVELS:
                    for argument in list(node.args) + [kw.value for kw in node.keywords]:
                        if isinstance(argument, ast.Name):
                            self._index_mutation(path, node, argument, "escape")
            # Fixed-point aliases are bounded by the number of declarations.
            for _ in range(3):
                for (candidate_path, _, target), assignments in self.assignments.items():
                    if candidate_path != path:
                        continue
                    for assignment in assignments:
                        value = assignment.value
                        callee = _name(value.func) if isinstance(value, ast.Call) else _name(value)
                        tail = callee.rsplit(".", 1)[-1]
                        if tail in {"getLogger", "get_logger", "LoggerAdapter"} or self.direct_imports[path].get(tail) in {"getLogger", "get_logger", "LoggerAdapter"} or callee in self.logger_names[path] or (tail in {"bind", "new", "child", "getChild", "opt", "with_name"} and callee.rsplit(".", 1)[0] in self.logger_names[path]):
                            self.logger_names[path].add(target)

    def _index_mutation(self, path: str, node: ast.AST, target: ast.AST, kind: str, require_field: bool = False) -> None:
        keys = []
        while isinstance(target, (ast.Attribute, ast.Subscript)):
            key = target.attr if isinstance(target, ast.Attribute) else target.slice.value if isinstance(target.slice, ast.Constant) else None
            keys.append(str(key) if key is not None else None)
            target = target.value
        if isinstance(target, ast.Name) and (keys or not require_field):
            scope = self.symbol(path, node)
            mutation_key = (path, scope, target.id)
            if mutation_key not in self.mutations:
                self._mutations_by_scope[(path, scope)].append((target.id, self.mutations[mutation_key]))
            self.mutations[mutation_key].append((node, list(reversed(keys)), kind))

    @staticmethod
    def position(node: ast.AST | int | tuple) -> tuple[int, int]:
        return node if isinstance(node, tuple) else (node, 0) if isinstance(node, int) else (node.lineno, node.col_offset)

    def conditional(self, path: str, node: ast.AST) -> bool:
        parent = self.parents[path].get(node)
        while parent is not None and not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            if isinstance(parent, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match, ast.IfExp)):
                return True
            parent = self.parents[path].get(parent)
        return False

    def symbol(self, path: str, node: ast.AST, include_self: bool = False) -> str:
        names = []
        current = node if include_self else self.parents.get(path, {}).get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(current.name)
            current = self.parents.get(path, {}).get(current)
        return ".".join(reversed(names)) or "<module>"

    def dependency(self, path: str, node: ast.AST, kind: str, symbol: str | None = None) -> dict:
        key = path, node, kind, symbol
        if key not in self._dependency_cache:
            self._dependency_cache[key] = {"path": path, "symbol": symbol or self.symbol(path, node, True), "start_line": node.lineno, "end_line": getattr(node, "end_lineno", node.lineno), "code": _snippet(self.files[path], node), "semantic_code": ast.dump(node, include_attributes=False), "kind": kind}
        # Dependency records contain only immutable scalars; callers own the dict.
        return dict(self._dependency_cache[key])

    def assignment(self, path: str, symbol: str, name: str, line: int | tuple) -> ast.AST | None:
        for scope in (symbol, "<module>"):
            eligible = [n for n in self.assignments.get((path, scope, name), []) if self.position(n) < self.position(line)]
            if eligible:
                return max(eligible, key=self.position)
        return None

    def origin(self, path: str, symbol: str, name: str, line: int | tuple, deps: list[dict], depth: int = 0) -> tuple[str, str, ast.AST | None]:
        assignment = self.assignment(path, symbol, name, line)
        if assignment is None or depth > 10:
            return symbol, name, None
        scope = self.symbol(path, assignment)
        deps.append(self.dependency(path, assignment, "argument_definition", name))
        if isinstance(assignment.value, ast.Name) and not self.conditional(path, assignment):
            return self.origin(path, scope, assignment.value.id, self.position(assignment), deps, depth + 1)
        return scope, name, assignment

    @staticmethod
    def field_value(key: str, value: Value) -> Value:
        value = deepcopy(value)
        kinds = _types(key) & SENSITIVE
        safe_value = value.known and (value.masked or value.boolean or any(s.startswith("aggregate_or_scalar_conversion:") for s in value.sanitization))
        if kinds and not safe_value:
            value.types.update(kinds)
            value.evidence.append({"source": key, "basis": "explicit_output_field", "types": sorted(kinds)})
        if value.masked and value.known:
            value.sanitization.append("constant_redaction:" + key)
        return value

    def write_field(self, value: Value, keys: list[str | None], addition: Value | None) -> Value:
        if not keys or keys[0] is None or value.fields is None:
            result = _join([value] + ([addition] if addition is not None else []))
            result.known = False
            result.gaps.append("mutation_shape_unresolved")
            return result
        fields = deepcopy(value.fields)
        key = keys[0]
        if len(keys) > 1:
            fields[key] = self.write_field(fields.get(key, Value()), keys[1:], addition)
        elif addition is None:
            fields.pop(key, None)
        else:
            fields[key] = self.field_value(key, addition)
        result = _join(list(fields.values()), fields=fields)
        result.sanitization.extend(value.sanitization)
        result.gaps.extend(value.gaps)
        if addition is None:
            result.sanitization.append("static_field_deletion:" + ".".join(str(k) for k in keys))
        return result

    def apply_mutations(self, path: str, symbol: str, name: str, line: int | tuple, result: Value, origin: tuple,
                        deps: list[dict], bindings: dict[str, Value], calls: int, depth: int) -> Value:
        root_scope, _, assignment = origin
        start = self.position(assignment) if assignment is not None else (0, 0)
        events = []
        for scope in dict.fromkeys((symbol, root_scope)):
            for receiver, mutations in self._mutations_by_scope.get((path, scope), ()):
                for event, keys, kind in mutations:
                    if not start < self.position(event) < self.position(line):
                        continue
                    alias_deps = []
                    if self.origin(path, scope, receiver, self.position(event), alias_deps) == origin:
                        events.append((event, keys, kind, receiver, alias_deps))
        for event, keys, kind, receiver, alias_deps in sorted(events, key=lambda e: self.position(e[0])):
            deps.extend(alias_deps)
            deps.append(self.dependency(path, event, "argument_mutation", receiver))
            def evaluate(expr):
                return self.value(path, expr, self.symbol(path, event), self.position(event), deps, bindings, calls, depth + 1)
            previous = result
            if kind == "set":
                result = self.write_field(result, keys, evaluate(event.value))
            elif kind == "delete":
                result = self.write_field(result, keys, None) if keys else Value(gaps=["deleted_binding:" + receiver])
            elif kind == "augment":
                addition = evaluate(event.value)
                if not keys and isinstance(event.op, ast.BitOr) and result.fields is not None and addition.fields is not None:
                    fields = {**result.fields, **addition.fields}
                    result = _join(list(fields.values()), fields=fields)
                elif not keys:
                    result = _join([result, addition])
                    result.known = False
                    result.gaps.append("augmented_operation_semantics_partial")
                else:
                    old = result
                    for key in keys:
                        old = old.fields.get(key, Value()) if old.fields is not None else Value()
                    result = self.write_field(result, keys, _join([old, addition]))
            elif kind == "escape":
                result = deepcopy(result)
                result.known = False
                result.fields = None
                result.gaps.append("call_side_effects_unresolved:" + _name(event.func))
            elif kind.startswith("call:"):
                method = kind[5:]
                target = result
                for key in keys:
                    target = target.fields.get(key, Value()) if target.fields is not None else Value()
                if method == "update":
                    additions = [evaluate(arg) for arg in event.args]
                    keyword_fields = {kw.arg: self.field_value(kw.arg, evaluate(kw.value)) for kw in event.keywords if kw.arg}
                    additions += [evaluate(kw.value) for kw in event.keywords if kw.arg is None]
                    if keyword_fields:
                        additions.append(_join(list(keyword_fields.values()), fields=keyword_fields))
                    for addition in additions:
                        if target.fields is not None and addition.fields is not None:
                            fields = {**target.fields, **addition.fields}
                            target = _join(list(fields.values()), fields=fields)
                        else:
                            target = _join([target, addition])
                            target.known = False
                            target.gaps.append("dictionary_update_unresolved")
                elif method in {"pop", "setdefault"} and event.args and isinstance(event.args[0], ast.Constant):
                    key = str(event.args[0].value)
                    if method == "pop":
                        target = self.write_field(target, [key], None)
                    elif target.fields is None or key not in target.fields:
                        target = self.write_field(target, [key], evaluate(event.args[1]) if len(event.args) > 1 else Value(known=True, masked=True))
                elif method == "clear" and target.fields is not None and not event.args and not event.keywords:
                    target = Value(fields={}, known=True, sanitization=["static_dictionary_clear"])
                else:
                    target = _join([target] + [evaluate(arg) for arg in event.args] + [evaluate(kw.value) for kw in event.keywords])
                    target.known = False
                    target.gaps.append("mutating_call_unresolved:" + method)
                result = self.write_field(result, keys, target) if keys else target
            # ponytail: no CFG. Conditional writes retain both possibilities, so
            # a conditional deletion/redaction can never certify a safe value.
            if self.conditional(path, event):
                result = _join([previous, result])
                result.known = False
                result.gaps.append("conditional_mutation_unresolved")
        return result

    def imported(self, path: str, callee: str) -> tuple[str, str] | None:
        first, _, rest = callee.partition(".")
        if first not in self.imports[path]:
            return None
        module, imported_name = self.imports[path][first]
        symbol = ".".join(filter(None, (imported_name, rest)))
        level = len(module) - len(module.lstrip("."))
        stripped = module.lstrip(".").replace(".", "/")
        if level:
            directory = posixpath.dirname(path)
            for _ in range(level - 1):
                directory = posixpath.dirname(directory)
            candidates = [posixpath.join(directory, stripped)]
        else:
            candidates = [stripped, posixpath.join(posixpath.dirname(path), stripped)]
        for base in candidates:
            for candidate in (base + ".py", posixpath.join(base, "__init__.py")):
                if candidate in self.trees:
                    return candidate, symbol
        suffix = stripped + ".py"
        matches = [p for p in self.trees if p.endswith("/" + suffix)]
        return (matches[0], symbol) if len(matches) == 1 else None

    def function(self, path: str, symbol: str, callee: str) -> tuple[str, ast.AST] | None:
        candidates = [(path, callee), (path, symbol.rsplit(".", 1)[0] + "." + callee)]
        imported = self.imported(path, callee)
        if imported:
            candidates.append(imported)
        for key in candidates:
            if key in self.functions:
                return key[0], self.functions[key]
        return None

    def model(self, path: str, name: str) -> tuple[str, ast.ClassDef] | None:
        if (path, name) in self.classes:
            return path, self.classes[(path, name)]
        target = self.imported(path, name)
        return (target[0], self.classes[target]) if target and target in self.classes else None

    def sink(self, path: str, call: ast.Call, allow_wrapper: bool = True) -> tuple[str, str] | None:
        name = _name(call.func)
        if name == "print":
            return "possible", "stdout"
        alias = self.direct_imports[path].get(name)
        if alias in LEVELS:
            return "confirmed", alias
        if isinstance(call.func, ast.Attribute) and call.func.attr in LEVELS:
            receiver = _name(call.func.value)
            if receiver in self.logger_names[path] or receiver.endswith("getLogger()") or receiver.endswith("get_logger()"):
                return "confirmed", call.func.attr
            if re.search(r"(?:^|\.)(?:logger|log|logging|console)$", receiver, re.I) or "logger" in receiver.lower():
                return "possible", call.func.attr
        if allow_wrapper:
            target = self.function(path, self.symbol(path, call), name)
            if target and any(isinstance(child, ast.Call) and self.sink(target[0], child, False) for child in ast.walk(target[1])):
                return "possible", "wrapper"
        return None

    def value(self, path: str, node: ast.AST | None, symbol: str, line: int, deps: list[dict], bindings: dict[str, Value] | None = None, calls: int = 0, depth: int = 0) -> Value:
        # Bound Values are mutable context: bypass memoization rather than keying
        # on their identities. Leaf cutoffs keep the existing unknown protocol.
        if bindings or node is None or depth > 10:
            return self._value(path, node, symbol, line, deps, bindings, calls, depth)
        owner = self._value_cache is None
        if owner:
            self._value_cache = {}
        # Node identity retains source coordinates (including synthetic nodes).
        # Snapshot, rules and configuration are fixed for this evaluation session.
        # Depth and calls preserve the exact remaining local/interprocedural budget:
        # a completed bounded result can still contain gaps and is never promoted
        # to a result with a larger budget. In-progress entries are never published;
        # recursive calls strictly increase depth, including on cyclic source flows.
        key = path, node, symbol, self.position(line), calls, depth
        try:
            cached = self._value_cache.get(key)
            if cached is not None:
                result, dependencies = cached
                deps.extend(dict(item) for item in dependencies)
                return deepcopy(result)
            dependencies: list[dict] = []
            result = self._value(path, node, symbol, line, dependencies, bindings, calls, depth)
            if not owner:
                # Preserve dependency order and multiplicity without retaining a
                # separate mutable dict for every repeated edge in the memo.
                records = []
                for item in dependencies:
                    record = tuple(item.items())
                    records.append(self._dependency_records.setdefault(record, record))
                self._value_cache[key] = deepcopy(result), records
            deps.extend(dependencies)
            return result
        finally:
            # Limit retention to a top-level query, and discard failed sessions.
            if owner:
                self._value_cache = None

    def _value(self, path: str, node: ast.AST | None, symbol: str, line: int, deps: list[dict], bindings: dict[str, Value] | None = None, calls: int = 0, depth: int = 0) -> Value:
        bindings = bindings or {}
        if node is None:
            return Value(known=True, masked=True)
        if depth > 10:
            return Value(gaps=["local_expression_depth_limit"])
        def evaluate(child: ast.AST | None, **kwargs: Any) -> Value:
            return self.value(path, child, symbol, line, deps, bindings, calls, depth + 1, **kwargs)
        if isinstance(node, ast.Constant):
            result = Value(known=True, masked=node.value is None or isinstance(node.value, str) and bool(MASKED.fullmatch(node.value)), boolean=isinstance(node.value, bool))
            if isinstance(node.value, str):
                for literal in re.finditer(r"(?i)\b(password|passwd|secret|api_key|access_token|authorization)\s*[:=]\s*([^\s,;]+)", node.value):
                    if not MASKED.fullmatch(literal.group(2)) and not literal.group(2).startswith(("%", "{", "<")):
                        result.types.add("credential")
                        result.evidence.append({"source": literal.group(1), "basis": "literal_credential_assignment", "types": ["credential"]})
            return result
        if isinstance(node, ast.Name):
            origin = self.origin(path, symbol, node.id, line, deps)
            scope, root_name, assignment = origin
            if assignment is not None and assignment.value is not None:
                result = self.value(path, assignment.value, scope, self.position(assignment), deps, bindings, calls, depth + 1)
                # A named payload literal is different from fixed log prose.
                # Retain only the supplied field-name hint, never scan arbitrary
                # strings or promote a synthetic/hard-coded value to a leak.
                if isinstance(assignment.value, ast.Constant) and not result.masked and not result.boolean:
                    kinds = _types(root_name) & {"personal_identifier", "medical_data", "financial_data", "precise_location", "biometric_data", "linkable_identifier"}
                    message_name = re.search(r"(?:message|msg|template|format|status|label)$", root_name, re.I)
                    if kinds and not message_name:
                        result.types.update(kinds)
                        result.evidence.append({"source": root_name, "basis": "identifier_only", "types": sorted(kinds)})
                        result.known = False
                        result.gaps.append("literal_payload_semantics_unverified")
                if self.conditional(path, assignment):
                    previous = self.value(path, ast.Name(id=root_name, ctx=ast.Load()), scope, self.position(assignment), deps, bindings, calls, depth + 1)
                    result = _join([previous, result])
                    result.known = False
                    result.gaps.append("conditional_assignment_unresolved")
                return self.apply_mutations(path, symbol, node.id, line, result, origin, deps, bindings, calls, depth)
            if root_name in bindings:
                return self.apply_mutations(path, symbol, node.id, line, deepcopy(bindings[root_name]), origin, deps, bindings, calls, depth)
            function = self.functions.get((path, symbol))
            if function:
                for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
                    if arg.arg == root_name and arg.annotation is not None:
                        model = self.model(path, _name(arg.annotation))
                        if model:
                            return self.apply_mutations(path, symbol, node.id, line, self.model_value(model[0], model[1], deps), origin, deps, bindings, calls, depth)
                        if _name(arg.annotation) == "bool" or _name(arg.annotation) in {"int", "float"} and not (_types(root_name) & SENSITIVE):
                            return Value(known=True, boolean=_name(arg.annotation) == "bool")
            types = _types(root_name)
            result = Value(types=types, evidence=[{"source": root_name, "basis": "identifier_only", "types": sorted(types)}], gaps=["unresolved_value:" + root_name])
            return self.apply_mutations(path, symbol, node.id, line, result, origin, deps, bindings, calls, depth)
        if isinstance(node, ast.Dict):
            fields: dict[str, Value] = {}
            extra = []
            for key, child in zip(node.keys, node.values):
                item = evaluate(child)
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    fields[str(key.value)] = self.field_value(key.value, item)
                else:
                    if key is None and item.fields is not None:
                        fields.update(item.fields)
                    else:
                        extra.append(item)
            result = _join(list(fields.values()) + extra, fields=fields if not extra else None)
            if extra:
                result.gaps.append("dynamic_dictionary_keys_or_unpack")
            return result
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            result = _join([evaluate(child) for child in node.elts])
            result.masked = not node.elts or result.masked
            return result
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            evaluate(node.operand)  # Dependency may change the boolean result.
            return Value(known=True, boolean=True)
        if isinstance(node, ast.Compare) and all(isinstance(op, (ast.Is, ast.IsNot, ast.In, ast.NotIn)) for op in node.ops):
            evaluate(node.left)
            for comparator in node.comparators:
                evaluate(comparator)
            return Value(known=True, boolean=True)
        if isinstance(node, ast.IfExp):
            evaluate(node.test)  # A guard is not the value emitted by this sink.
            branches = [evaluate(node.body), evaluate(node.orelse)]
            result = _join(branches)
            result.masked = all(branch.masked for branch in branches)
            return result
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            root = evaluate(node.value)
            key = node.attr if isinstance(node, ast.Attribute) else node.slice.value if isinstance(node.slice, ast.Constant) else None
            if key is not None and root.fields is not None and str(key) in root.fields:
                return root.fields[str(key)]
            kind = (_types(str(key)) | identifier_types(_snippet(self.files[path], node))) if key is not None else set()
            # Attribute access restricts the value; do not propagate all fields of
            # user into user.id, which would make a real allowlist look unsafe.
            if key is not None:
                return Value(types=kind, known=False, evidence=[{"source": _snippet(self.files[path], node), "basis": "explicit_sensitive_access", "types": sorted(kind)}], gaps=["field_runtime_value_unknown"])
            root.gaps.append("dynamic_subscript")
            return root
        if isinstance(node, ast.Call):
            callee = _name(node.func)
            args = [evaluate(arg) for arg in node.args] + [evaluate(k.value) for k in node.keywords]
            if callee in {"len", "bool"}:
                return Value(known=True, boolean=callee == "bool", sanitization=["aggregate_or_scalar_conversion:" + callee])
            if callee == "dict":
                fields, opaque = {}, []
                for value in args[:len(node.args)]:
                    if value.fields is not None:
                        fields.update(value.fields)
                    else:
                        opaque.append(value)
                for keyword, value in zip(node.keywords, args[len(node.args):]):
                    if keyword.arg is not None:
                        fields[keyword.arg] = self.field_value(keyword.arg, value)
                    elif value.fields is not None:
                        fields.update(value.fields)
                    else:
                        opaque.append(value)
                result = _join(list(fields.values()) + opaque, fields=fields if not opaque else None)
                if opaque:
                    result.known = False
                    result.masked = False
                    result.gaps.append("dictionary_constructor_shape_unresolved")
                return result
            if callee in {"str", "repr", "vars", "asdict", "json.dumps", "dataclasses.asdict"}:
                result = _join(args)
                if len(args) == 1:
                    result.fields = args[0].fields
                if callee in {"vars", "asdict", "dataclasses.asdict"}:
                    result.gaps = [gap for gap in result.gaps if gap != "object_representation_unresolved"]
                return result
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"copy", "model_dump", "dict", "__str__", "__repr__"}:
                root = evaluate(node.func.value)
                return root
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args and isinstance(node.args[0], ast.Constant):
                root = evaluate(node.func.value)
                key = str(node.args[0].value)
                if root.fields is not None and key in root.fields:
                    return root.fields[key]
                source = _name(node.func.value) + "." + key
                kinds = _types(key) | identifier_types(source)
                return Value(types=kinds, known=False, evidence=[{"source": source, "basis": "explicit_sensitive_access", "types": sorted(kinds)}], gaps=["field_runtime_value_unknown"])
            target = self.function(path, symbol, callee)
            if target:
                target_path, function = target
                deps.append(self.dependency(target_path, function, "function", self.symbol(target_path, function, True)))
                if calls >= 1:
                    result = _join(args)
                    result.known = False
                    result.gaps.append("interprocedural_depth_limit:" + callee)
                    return result
                bound = {param.arg: value for param, value in zip((*function.args.posonlyargs, *function.args.args), args)}
                for keyword, value in zip(node.keywords, args[len(node.args):]):
                    if keyword.arg:
                        bound[keyword.arg] = value
                # ponytail: only a straight-line return is interpreted; branches,
                # mutation and dynamic dispatch require a later CFG analysis.
                returns = [child for child in function.body if isinstance(child, ast.Return)]
                complex_body = any(isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.Match)) for child in function.body) if hasattr(ast, "Match") else any(isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.With)) for child in function.body)
                if len(returns) == 1 and not complex_body:
                    result = self.value(target_path, returns[0].value, self.symbol(target_path, function, True), self.position(returns[0]), deps, bound, calls + 1, depth + 1)
                    if isinstance(returns[0].value, ast.Dict):
                        result.sanitization.append("static_field_projection:" + callee)
                    return result
                result = _join(args)
                result.known = False
                result.gaps.append("complex_function_body:" + callee)
                return result
            model = self.model(path, callee)
            if model:
                value = self.model_value(model[0], model[1], deps)
                return _join([value] + args, fields=value.fields)
            result = _join(args)
            result.known = False
            result.masked = False
            result.gaps.append("unresolved_call:" + callee)
            if re.search(r"sanitize|redact|mask", callee, re.I):
                result.sanitization.append("unverified_named_sanitizer:" + callee)
            return result
        if isinstance(node, (ast.JoinedStr, ast.FormattedValue, ast.BinOp, ast.UnaryOp, ast.BoolOp)):
            return _join([evaluate(child) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)])
        return Value(gaps=["unsupported_expression:" + type(node).__name__])

    def model_value(self, path: str, model: ast.ClassDef, deps: list[dict]) -> Value:
        deps.append(self.dependency(path, model, "data_model", model.name))
        fields = {}
        for child in model.body:
            if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                types = _types(child.target.id)
                scalar = _name(child.annotation) in {"int", "float", "bool"} and not types
                fields[child.target.id] = Value(types=types, known=scalar, boolean=_name(child.annotation) == "bool", evidence=[] if scalar else [{"source": model.name + "." + child.target.id, "basis": "declared_model_field", "types": sorted(types)}], gaps=[] if scalar or types else ["model_field_type_unclassified"])
        if not fields:
            return Value(types={"opaque_object"}, gaps=["model_fields_unresolved:" + model.name])
        result = _join(list(fields.values()), fields=fields)
        is_dataclass = any((_name(decorator.func) if isinstance(decorator, ast.Call) else _name(decorator)).endswith("dataclass") for decorator in model.decorator_list)
        custom_repr = any(isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name in {"__str__", "__repr__"} for child in model.body)
        hidden_repr = any(isinstance(child, ast.AnnAssign) and isinstance(child.value, ast.Call) and any(k.arg == "repr" and isinstance(k.value, ast.Constant) and k.value.value is False for k in child.value.keywords) for child in model.body)
        if not is_dataclass or custom_repr or hidden_repr:
            result.gaps.append("object_representation_unresolved")
        return result

    def entities(self) -> list[dict]:
        output = []
        counts: Counter = Counter()
        for path, tree in sorted(self.trees.items()):
            for call in sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)), key=lambda node: (node.lineno, node.col_offset)):
                sink = self.sink(path, call)
                if not sink:
                    continue
                status, level = sink
                symbol = self.symbol(path, call)
                deps: list[dict] = []
                values = [self.value(path, arg, symbol, self.position(call), deps) for arg in call.args]
                values += [self.field_value(k.arg, self.value(path, k.value, symbol, self.position(call), deps))
                           if k.arg else self.value(path, k.value, symbol, self.position(call), deps) for k in call.keywords]
                if level == "exception" or any(k.arg in {"exc_info", "stack_info"} and not (isinstance(k.value, ast.Constant) and not k.value.value) for k in call.keywords):
                    values.append(Value(types={"exception_data"}, evidence=[{"source": "current_exception_or_stack", "basis": "implicit_exception_output", "types": ["exception_data"]}], gaps=["exception_contents_unresolved"]))
                receiver = _name(call.func.value) if isinstance(call.func, ast.Attribute) else ""
                binding_position = self.position(call)
                seen_receivers = set()
                while receiver and receiver not in seen_receivers:
                    seen_receivers.add(receiver)
                    logger_assignment = self.assignment(path, symbol, receiver, binding_position)
                    if logger_assignment is None:
                        break
                    deps.append(self.dependency(path, logger_assignment, "logger_binding", receiver))
                    initializer = logger_assignment.value
                    binding_position = self.position(logger_assignment)
                    if isinstance(initializer, ast.Name):
                        receiver = initializer.id
                        continue
                    if isinstance(initializer, ast.Call):
                        tail = _name(initializer.func).rsplit(".", 1)[-1]
                        if tail == "LoggerAdapter" and len(initializer.args) > 1:
                            values.append(self.value(path, initializer.args[1], symbol, binding_position, deps))
                        if tail in {"bind", "child", "new"}:
                            values.extend(self.value(path, arg, symbol, self.position(call), deps) for arg in initializer.args)
                            values.extend(self.field_value(k.arg, self.value(path, k.value, symbol, self.position(call), deps))
                                          if k.arg else self.value(path, k.value, symbol, self.position(call), deps) for k in initializer.keywords)
                        if tail == "LoggerAdapter" and initializer.args:
                            receiver = _name(initializer.args[0])
                            continue
                        if tail in {"bind", "child", "new", "getChild", "opt", "with_name"} and isinstance(initializer.func, ast.Attribute):
                            receiver = _name(initializer.func.value)
                            continue
                    break
                if level == "wrapper":
                    target = self.function(path, symbol, _name(call.func))
                    if target:
                        deps.append(self.dependency(target[0], target[1], "wrapper"))
                triggers = ["requires_logger_level:" + level]
                child = call
                parent = self.parents[path].get(call)
                while parent is not None and not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module, ast.Lambda)):
                    if isinstance(parent, (ast.If, ast.IfExp)) and child is not parent.test:
                        negative = child in parent.orelse if isinstance(parent, ast.If) else child is parent.orelse
                        condition = _snippet(self.files[path], parent.test)
                        triggers.append("condition:" + ("not (" + condition + ")" if negative else condition))
                        deps.append(self.dependency(path, parent.test, "condition", symbol))
                        self.value(path, parent.test, symbol, self.position(parent), deps)
                    if isinstance(parent, ast.While):
                        triggers.append("while:" + _snippet(self.files[path], parent.test))
                        deps.append(self.dependency(path, parent.test, "condition", symbol))
                        self.value(path, parent.test, symbol, self.position(parent), deps)
                    if isinstance(parent, (ast.For, ast.AsyncFor)):
                        triggers.append("for:" + _snippet(self.files[path], parent.iter))
                        deps.append(self.dependency(path, parent.iter, "loop_iterable", symbol))
                        self.value(path, parent.iter, symbol, self.position(parent), deps)
                    if isinstance(parent, (ast.With, ast.AsyncWith)):
                        for item in parent.items:
                            triggers.append("with:" + _snippet(self.files[path], item.context_expr))
                            deps.append(self.dependency(path, item.context_expr, "context_manager", symbol))
                    if isinstance(parent, ast.Try):
                        triggers.append("finally" if child in parent.finalbody else "try_else" if child in parent.orelse else "try")
                    if isinstance(parent, ast.ExceptHandler):
                        triggers.append("exception_handler:" + (_name(parent.type) if parent.type else "any"))
                    if isinstance(parent, ast.match_case):
                        triggers.append("case:" + _snippet(self.files[path], parent.pattern))
                        if parent.guard is not None:
                            triggers.append("case_guard:" + _snippet(self.files[path], parent.guard))
                            deps.append(self.dependency(path, parent.guard, "condition", symbol))
                    child = parent
                    parent = self.parents[path].get(parent)
                merged = _join(values)
                explicit = any(e.get("basis") != "identifier_only" and set(e.get("types", [])) & SENSITIVE for e in merged.evidence)
                if "object_representation_unresolved" in merged.gaps:
                    explicit = any(e.get("basis") in {"explicit_output_field", "explicit_sensitive_access"} and set(e.get("types", [])) & SENSITIVE for e in merged.evidence)
                assessment = "supported" if explicit else "possible" if merged.types else "not_supported" if merged.known else "unknown"
                message = next((arg.value for arg in call.args if isinstance(arg, ast.Constant) and isinstance(arg.value, str)), "<dynamic>")
                message_hash = hashlib.sha256(message.encode()).hexdigest()[:16]
                count_key = path, symbol, message_hash
                ordinal = counts[count_key]
                counts[count_key] += 1
                unique_deps = { (d["path"], d["symbol"], d["start_line"], d["end_line"], d["kind"]): d for d in deps }
                output.append({
                    "path": path, "symbol": symbol, "callee": _name(call.func), "level": level,
                    "start_line": call.lineno, "end_line": call.end_lineno,
                    "statement": _snippet(self.files[path], call),
                    "semantic_statement": ast.dump(call, include_attributes=False),
                    "identity": f"{symbol}:{message_hash}:{ordinal}",
                    "message_template": message, "parser_status": "python_ast",
                    "log_detection_status": status, "dependencies": list(unique_deps.values()),
                    "data_types": sorted(merged.types), "privacy_assessment": assessment,
                    "source_to_sink": [dict(e, sink=_name(call.func), sink_path=path, sink_line=call.lineno) for e in merged.evidence],
                    "existing_sanitization": sorted(set(merged.sanitization)),
                    "trigger_conditions": triggers, "matched_rules": ["runtime_sink:" + status, "bounded_source_to_sink:" + assessment],
                    "missing_evidence": sorted(set(merged.gaps + ["runtime_reachability_and_output_access_unverified"])),
                    "analysis_depth": 1, "analysis_method": "bounded_static", "reverse_dependency_coverage": "partial",
                })
        return [annotate_entity(entity) for entity in output]


def _mask_lexical(source: str, language: str = "python") -> str:
    """Keep offsets/newlines while masking comments and quoted text."""
    if language == "csharp":
        return _csharp_lexical(source)[0]
    if language in {"javascript", "typescript", "jsx", "tsx", "go", "java"}:
        lexer = JavaLexer() if language == "java" else GoLexer() if language == "go" else TypeScriptLexer() if language in {"typescript", "tsx"} else JavascriptLexer()
        # ponytail: tokenization retains template expressions and masks regex
        # literals; aliases, value flow and JSX semantics still require an AST.
        return "".join(
            "".join(char if char in "\r\n" else " " for char in value)
            if kind in Comment or (kind in String and kind not in String.Interpol) else value
            for _, kind, value in lexer.get_tokens_unprocessed(source)
        )
    pattern = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`|\#[^\n]*")
    return pattern.sub(lambda match: "".join("\n" if char == "\n" else " " for char in match.group()), source)


def _balanced_end(masked: str, start: int, opening: str = "(", closing: str = ")") -> int | None:
    balance = 0
    for position in range(start, len(masked)):
        char = masked[position]
        if char == opening:
            balance += 1
        elif char == closing:
            balance -= 1
            if balance == 0:
                return position + 1
    return None


def _lexical_arguments(masked: str, start: int, end: int) -> list[tuple[int, int]]:
    """Split an already balanced call, retaining original source offsets."""
    parts, depth, begin = [], 0, start + 1
    for position in range(begin, end - 1):
        char = masked[position]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append((begin, position))
            begin = position + 1
    if begin < end - 1:
        parts.append((begin, end - 1))
    return parts


def _go_entities(path: str, source: str) -> tuple[list[dict], list[dict]]:
    # ponytail: lexical Go calls and one assignment hop; add a Go AST/value-flow
    # backend before treating aliases, method dispatch or sanitizers as proven.
    masked = _mask_lexical(source, "go")
    strings = {offset: value for offset, kind, value in GoLexer().get_tokens_unprocessed(source)
               if kind in String and value[:1] in {'"', '`'}}
    packages = {"log", "log/slog", "github.com/sirupsen/logrus", "go.uber.org/zap",
                "github.com/rs/zerolog", "github.com/rs/zerolog/log"}
    imports = {}
    for match in re.finditer(r"\bimport\b[^\S\r\n]*(?:\([\s\S]*?\)|[^\n;]*)", masked):
        for offset, value in strings.items():
            if match.start() <= offset < match.end() and value[1:-1] in packages:
                prefix = masked[match.start() + len("import"):offset].rsplit("\n", 1)[-1].rsplit(";", 1)[-1].strip(" (\t\r")
                alias = prefix if re.fullmatch(r"[A-Za-z_]\w*", prefix) else value[1:-1].rsplit("/", 1)[-1]
                imports[alias] = value[1:-1]
    calls = list(re.finditer(r"\b((?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(", masked))
    declarations = list(re.finditer(r"(?m)(?:^|(?<=[;{}]))[ \t]*(?:var\s+)?([A-Za-z_]\w*)(?:\s*,\s*_)?(?:[ \t]+[A-Za-z_][\w.*\[\]]*)?[ \t]*(?::=|=(?!=))", masked))
    positions = sorted({match.start() for match in calls + declarations})
    scopes, stack, cursor = {}, [], 0
    for position in positions:
        for index in range(cursor, position):
            if masked[index] == "{":
                stack.append(index)
            elif masked[index] == "}" and stack:
                stack.pop()
        scopes[position], cursor = tuple(stack), position
    definitions = defaultdict(list)
    for declaration in declarations:
        end, depth = declaration.end(), 0
        while end < len(masked):
            if end in strings:
                end += len(strings[end])
                continue
            char = masked[end]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                if depth == 0:
                    break
                depth -= 1
            if char in ";\n" and depth == 0:
                break
            end += 1
        definitions[declaration.group(1)].append((declaration.start(), end, scopes[declaration.start()]))

    def logger_receiver(receiver: str) -> bool:
        leaf = receiver.rsplit(".", 1)[-1]
        package = imports.get(receiver)
        return bool(re.search(r"(?:^|_)(?:log|logger|logging|slog|cclog)$|(?:Log|Logger)$", leaf)) or package in {"log", "log/slog", "github.com/sirupsen/logrus", "github.com/rs/zerolog/log"}

    def literal(part: tuple[int, int]) -> str | None:
        begin, end = part
        while begin < end and source[begin].isspace():
            begin += 1
        value = strings.get(begin)
        if value is not None and not source[begin + len(value):end].strip():
            return value[1:-1]
        return None

    def names_in(begin: int, end: int, ignored: tuple[tuple[int, int], ...] | list[tuple[int, int]] = ()) -> set[str]:
        names = set()
        for name in re.finditer(r"\b[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*", masked[begin:end]):
            if any(left <= begin + name.start() < right for left, right in ignored):
                continue
            if re.match(r"\s*\(", masked[begin + name.end():end]):
                continue
            value = re.sub(r"\s", "", name.group())
            if value not in {"nil", "true", "false", "var", "const", "return", "string", "int", "bool"}:
                names.add(value)
        return names

    def definition(name: str, position: int) -> tuple | None:
        scope = scopes[position]
        eligible = [item for item in definitions.get(name, []) if item[1] < position and scope[:len(item[2])] == item[2]]
        return eligible[-1] if eligible else None

    entities, counts, consumed = [], Counter(), -1
    gaps = [{"path": path, "reason": "lexical_fallback_without_ast", "details": "Go: no verified method dispatch, cross-file value flow, or sanitization semantics"}]
    levels = re.compile(r"^(?:Debug|Info|Warn|Warning|Error|Fatal|Panic|Trace|Print|Log)(?:f|ln|w|Context|Attrs)?$")
    for match in calls:
        if match.start() < consumed:
            continue
        receiver = re.sub(r"\s", "", match.group(1))
        binding = definition(receiver, match.start())
        binding_code = masked[binding[0]:binding[1]] if binding else ""
        from_constructor = bool(binding and any(re.search(r"\b" + re.escape(alias) + r"\s*\.\s*(?:New\w*|Default|L|S)\s*\(", binding_code) for alias in imports))
        if not (logger_receiver(receiver) or from_constructor or imports.get(receiver) == "go.uber.org/zap" and match.group(2) in {"L", "S"}):
            continue
        # zap.Error(err) is an attribute constructor, not a log emission.
        if imports.get(receiver) in {"go.uber.org/zap", "github.com/rs/zerolog"} and match.group(2) not in {"L", "S"}:
            continue
        chain, current, end = [], match, None
        while current:
            opening = current.end() - 1
            end = _balanced_end(masked, opening)
            if end is None:
                gaps.append({"path": path, "reason": "unbalanced_log_call", "line": source.count("\n", 0, match.start()) + 1})
                break
            method = current.group(2) if current is match else current.group(1)
            chain.append((method, opening, end))
            current = re.compile(r"\s*\.\s*([A-Za-z_]\w*)\s*\(").match(masked, end)
        if end is None or not chain:
            continue
        emission = next((item for item in reversed(chain) if levels.fullmatch(item[0]) or item[0] in {"Msg", "Msgf", "Send"}), None)
        if emission is None or chain[-1][0] in {"With", "WithField", "WithFields", "Logger"}:
            continue
        if (len(chain) > 1 and chain[-1] != emission) or ("zerolog" in imports.get(receiver, "") and emission[0] not in {"Msg", "Msgf", "Send"}):
            gaps.append({"path": path, "reason": "go_log_builder_without_terminal", "line": source.count("\n", 0, match.start()) + 1})
            continue
        consumed = end
        emission_parts = _lexical_arguments(masked, emission[1], emission[2])
        slog_receiver = imports.get(receiver) == "log/slog" or receiver.rsplit(".", 1)[-1] == "slog" or any(package == "log/slog" and re.search(r"\b" + re.escape(alias) + r"\s*\.", binding_code) for alias, package in imports.items())
        message_index = 2 if emission[0] == "LogAttrs" or slog_receiver and emission[0] == "Log" else 1 if emission[0].endswith("Context") else 0
        deps, ranges = [], [(match.end(), end - 1)]
        names = names_in(*ranges[0], emission_parts[:message_index])
        for name in sorted({name.split(".")[0] for name in names} | {receiver}):
            found = definition(name, match.start())
            if found:
                begin, finish, _ = found
                deps.append({"path": path, "symbol": name, "start_line": source.count("\n", 0, begin) + 1,
                             "end_line": source.count("\n", 0, finish) + 1, "code": source[begin:finish],
                             "kind": "logger_binding" if name == receiver else "argument_definition"})
                # Exactly one assignment hop; further aliases stay unresolved.
                ranges.append((begin, finish))
                names.update(names_in(begin, finish))
        fields = set()
        for method, opening, close in chain:
            if method == "WithField":
                parts = _lexical_arguments(masked, opening, close)
                if len(parts) >= 2 and literal(parts[0]) is not None and not (literal(parts[1]) is not None and MASKED.fullmatch(literal(parts[1]))):
                    fields.add(literal(parts[0]))
        for begin, finish in ranges:
            # Named Go map fields are output keys, not log-message prose.
            for offset, value in strings.items():
                tail = offset + len(value)
                colon = re.match(r"\s*:", masked[tail:finish])
                if begin <= offset < finish and colon:
                    value_offset = tail + colon.end()
                    while value_offset < finish and source[value_offset].isspace():
                        value_offset += 1
                    field_value = strings.get(value_offset)
                    if field_value and MASKED.fullmatch(field_value[1:-1]) and masked[value_offset + len(field_value):finish].lstrip().startswith((",", "}")):
                        continue
                    fields.add(value[1:-1])
            for attr in re.finditer(r"\b(?:[A-Za-z_]\w*\s*\.)?(?:String|Stringer|Any|Int\d*|Uint\d*|Bool|Float\d*|Str|Bytes|Interface|Time|Duration|WithField)\s*\(", masked[begin:finish]):
                opening = begin + attr.end() - 1
                close = _balanced_end(masked, opening)
                parts = _lexical_arguments(masked, opening, close) if close else []
                if len(parts) >= 2 and literal(parts[0]) is not None and not (literal(parts[1]) is not None and MASKED.fullmatch(literal(parts[1]))):
                    fields.add(literal(parts[0]))
        structured = slog_receiver or emission[0].endswith(("w", "Context", "Attrs"))
        if structured:
            for index in range(message_index + 1, len(emission_parts) - 1, 2):
                key, value = literal(emission_parts[index]), literal(emission_parts[index + 1])
                if key is not None and not (value is not None and MASKED.fullmatch(value)):
                    fields.add(key)
        # Field/identifier evidence stays low confidence, even with a known API.
        names.update(field for field in fields if re.fullmatch(r"[A-Za-z_][\w.-]*", field))
        types = set().union(*(_types(name) for name in names)) if names else set()
        message = literal(emission_parts[message_index]) if len(emission_parts) > message_index else None
        message = message if message is not None else "<dynamic>"
        template = hashlib.sha256(message.encode()).hexdigest()[:16]
        ordinal, level = counts[template], emission[0].lower()
        counts[template] += 1
        statement, callee = source[match.start():end], receiver + "." + emission[0]
        entities.append(annotate_entity({"path": path, "symbol": "<lexical_scope_unknown>", "callee": callee, "level": level,
            "start_line": source.count("\n", 0, match.start()) + 1, "end_line": source.count("\n", 0, end) + 1,
            "statement": statement, "semantic_statement": statement.strip(), "identity": f"<lexical_scope_unknown>:{template}:{ordinal}",
            "message_template": message, "parser_status": "lexical_only", "log_detection_status": "possible", "dependencies": deps,
            "data_types": sorted(types), "privacy_assessment": "possible" if types else "unknown",
            "source_to_sink": [{"source": name, "basis": "lexical_identifier_only", "sink": callee, "types": sorted(_types(name))} for name in sorted(names)],
            "existing_sanitization": [], "trigger_conditions": ["requires_logger_level:" + level, "lexical_trigger_conditions_unresolved"],
            "matched_rules": ["balanced_multiline_go_lexical_sink"],
            "missing_evidence": ["go_semantics_unparsed", "go_one_hop_lexical_only", "go_cross_file_dependencies_unresolved", "runtime_reachability_and_output_access_unverified"],
            "analysis_depth": 1, "analysis_method": "bounded_lexical", "reverse_dependency_coverage": "partial"}))
    return entities, gaps


def _csharp_string(source: str, start: int, depth: int = 0) -> dict | None:
    """Bound string text without executing C#; only simple interpolation names."""
    prefix = re.compile(r'(\$*)("{3,})|((?:\$@|@\$|@|\$)?)(")').match(source, start)
    if not prefix:
        return None
    body_start, names, gaps = prefix.end(), [], []
    interpolated = "$" in prefix.group()
    if prefix.group(2):
        close = source.find(prefix.group(2), body_start)
        if interpolated:
            gaps.append("csharp_raw_interpolation_unparsed")
        end = close + len(prefix.group(2)) if close >= 0 else len(source)
        if close < 0:
            gaps.append("csharp_unterminated_string")
        return {"end": end, "body": source[body_start:close if close >= 0 else end],
                "interpolated": interpolated, "names": names, "gaps": gaps}
    verbatim, index = "@" in prefix.group(), body_start
    if depth > 20:
        return {"end": len(source), "body": "", "interpolated": interpolated, "names": [], "gaps": ["csharp_nested_string_budget_exceeded"]}
    while index < len(source):
        char = source[index]
        if not verbatim and (char in "\r\n" or char == "\\" and index + 1 < len(source) and source[index + 1] in "\r\n"):
            # An ordinary C# string cannot continue over a physical newline.
            # Keep the unread remainder opaque instead of stealing a quote from
            # later code and turning broken history into a no-log snapshot.
            return {"end": len(source), "body": source[body_start:index], "interpolated": interpolated,
                    "names": names, "gaps": gaps + ["csharp_unterminated_string"]}
        if char == "\\" and not verbatim:
            index += 2
            continue
        if char == '"':
            if verbatim and source.startswith('""', index):
                index += 2
                continue
            return {"end": index + 1, "body": source[body_start:index], "interpolated": interpolated, "names": names, "gaps": gaps}
        if interpolated and source.startswith("{{", index):
            index += 2
            continue
        if interpolated and char == "{":
            begin, balance = index + 1, 1
            index += 1
            while index < len(source) and balance:
                nested = _csharp_string(source, index, depth + 1) if source[index] in '$@"' else None
                if nested:
                    index = nested["end"]
                    continue
                if source.startswith("//", index):
                    line_end = source.find("\n", index)
                    index = line_end if line_end >= 0 else len(source)
                    continue
                if source.startswith("/*", index):
                    comment_end = source.find("*/", index + 2)
                    index = comment_end + 2 if comment_end >= 0 else len(source)
                    continue
                if source[index] == "'":
                    rune = re.compile(r"'(?:\\.|[^'\\])*'").match(source, index)
                    if rune:
                        index = rune.end()
                        continue
                balance += (source[index] == "{") - (source[index] == "}")
                index += 1
            if balance:
                gaps.append("csharp_unterminated_interpolation")
                break
            expression = source[begin:index - 1]
            simple = re.fullmatch(r"\s*(@?[A-Za-z_]\w*(?:(?:\?|!)?\s*\.\s*@?[A-Za-z_]\w*)*)(?:\s*,\s*-?\d+)?(?:\s*:[^{}]*)?\s*", expression)
            if simple:
                names.append(re.sub(r"[\s@?!]", "", simple.group(1)))
            else:
                gaps.append("csharp_complex_interpolation_unparsed")
            continue
        index += 1
    return {"end": len(source), "body": source[body_start:], "interpolated": interpolated,
            "names": names, "gaps": gaps + ["csharp_unterminated_string"]}


def _csharp_lexical(source: str) -> tuple[str, dict[int, dict], list[str]]:
    # Pygments supplies comments/string starts. Correct its nested interpolation
    # and unequal raw-quote boundaries before looking for executable calls.
    lexer_source = (" " + source[1:]) if source.startswith("\ufeff") else source
    lexer_source = re.sub(r"(?m)^[ \t]*#nullable\b[^\r\n]*", lambda match: " " * len(match.group()), lexer_source)
    masked, strings, gaps, covered = list(lexer_source), {}, set(), 0

    def hide(begin: int, end: int) -> None:
        masked[begin:end] = [char if char in "\r\n" else " " for char in source[begin:end]]

    lexer = CSharpLexer()

    def tokens_from(begin: int):
        return ((begin + offset, kind, value) for offset, kind, value in lexer.get_tokens_unprocessed(lexer_source[begin:] + "\n"))

    tokens = tokens_from(0)
    while True:
        token = next(tokens, None)
        if token is None:
            break
        offset, kind, value = token
        if offset < covered:
            if offset + len(value) > covered:
                # A Pygments token may cross a corrected string/attribute end.
                # Restart there; dropping that token would also drop live code.
                tokens = tokens_from(covered)
            continue
        if offset >= len(source):
            continue
        end = min(len(source), offset + len(value))
        previous = offset - 1
        while previous >= 0 and masked[previous].isspace():
            previous -= 1
        declaration_boundary = previous < 0 or masked[previous] in ";{}]"
        attribute_declaration = False
        literal = _csharp_string(source, offset) if (kind in String and kind not in String.Char) or kind in Error else None
        if literal:
            strings[offset], end = literal, literal["end"]
            gaps.update(literal["gaps"])
        elif source[offset] == "[" and (kind in Name.Attribute or value == "[" and declaration_boundary):
            # Pygments stops an attribute at the first ], even inside the
            # valid route string "api/[controller]". Consume the full bracket
            # span so the remaining closing quote cannot become a new string.
            attribute_declaration = declaration_boundary
            end, balance = offset + 1, 1
            while end < len(source) and balance:
                if source[end] == "'":
                    rune = re.compile(r"'(?:\\.|[^'\\])*'").match(source, end)
                    if rune:
                        hide(end, rune.end())
                        end = rune.end()
                        continue
                nested = _csharp_string(source, end) if source[end] in '$@"' else None
                if nested:
                    if not attribute_declaration:
                        strings[end] = nested
                        hide(end, nested["end"])
                    end = nested["end"]
                    gaps.update(nested["gaps"])
                    continue
                if source.startswith("//", end):
                    next_line = source.find("\n", end)
                    finish = next_line if next_line >= 0 else len(source)
                    hide(end, finish)
                    end = finish
                    continue
                if source.startswith("/*", end):
                    close = source.find("*/", end + 2)
                    finish = close + 2 if close >= 0 else len(source)
                    hide(end, finish)
                    end = finish
                    continue
                balance += (source[end] == "[") - (source[end] == "]")
                end += 1
            if balance:
                gaps.add("csharp_unterminated_attribute")
            covered = end
        if literal or kind in String or kind in Comment or attribute_declaration:
            hide(offset, end)
            covered = end
        elif kind in Error:
            gaps.add("csharp_lexer_error")
    return "".join(masked), strings, sorted(gaps)


def _csharp_entities(path: str, source: str) -> tuple[list[dict], list[dict]]:
    # ponytail: single-file lexical calls/one assignment hop; C# overloads,
    # generated logging methods and cross-file flow need a semantic backend.
    masked, strings, lexical_gaps = _csharp_lexical(source)
    levels = r"Log(?:Trace|Debug|Information|Warning|Error|Critical)?|Trace|Debug|Info|Information|Warn|Warning|Error|Fatal|Critical|Verbose|Write"
    calls = list(re.finditer(r"(?<![\w@])((?:@?[A-Za-z_]\w*\s*(?:\?\.|\.)\s*)*@?[A-Za-z_]\w*)\s*(?:\?\.|\.)\s*(" + levels + r")\s*(?:<[^<>;\n]+>)?\s*\(", masked))
    declarations = list(re.finditer(r"(?m)(?:^|(?<=[;{}]))[ \t]*(?:(?:var|string|object|dynamic|[A-Z][\w.]*)(?:<[^<>;\n]+>)?[?\[\]]*\s+)?(@?[A-Za-z_]\w*)\s*=(?!=|>)", masked))
    scopes, stack, cursor = {}, [], 0
    for position in sorted({match.start() for match in calls + declarations}):
        for index in range(cursor, position):
            if masked[index] == "{":
                stack.append(index)
            elif masked[index] == "}" and stack:
                stack.pop()
        scopes[position], cursor = tuple(stack), position
    definitions = defaultdict(list)
    for declaration in declarations:
        end, depth = declaration.end(), 0
        while end < len(masked):
            char = masked[end]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                if depth == 0:
                    break
                depth -= 1
            if char == ";" and depth == 0:
                break
            end += 1
        definitions[declaration.group(1).lstrip("@")].append((declaration.start(), declaration.end(), end, scopes[declaration.start()]))
    typed_loggers = {match.group(1) for match in re.finditer(r"\b(?:ILogger|NLog\.Logger)(?:\s*<[^<>;\n]+>)?\s+(@?[A-Za-z_]\w*)", masked)}
    exception_bindings = []
    for binding in re.finditer(r"\bcatch\s*\(\s*(?:[A-Za-z_]\w*\.)*[A-Za-z_]*Exception\s+([A-Za-z_]\w*)\s*\)\s*\{", masked):
        close = _balanced_end(masked, binding.end() - 1, "{", "}")
        if close:
            exception_bindings.append((binding.group(1), binding.end(), close))

    def definition(name: str, position: int) -> tuple | None:
        scope = scopes[position]
        eligible = [item for item in definitions.get(name, []) if item[2] < position and scope[:len(item[3])] == item[3]]
        return eligible[-1] if eligible else None

    def literal(part: tuple[int, int]) -> dict | None:
        begin, end = part
        while begin < end and source[begin].isspace():
            begin += 1
        found = strings.get(begin)
        return found if found and found["end"] <= end and not source[found["end"]:end].strip() else None

    def names_in(begin: int, end: int) -> set[str]:
        names = set()
        for match in re.finditer(r"@?[A-Za-z_]\w*(?:(?:\?|!)?\s*\.\s*@?[A-Za-z_]\w*)*", masked[begin:end]):
            if re.match(r"\s*(?:<[^<>;]+>)?\s*\(", masked[begin + match.end():end]):
                continue
            name = re.sub(r"[\s@?!]", "", match.group())
            if name not in {"null", "true", "false", "new", "string", "object", "var", "dynamic", "nameof", "typeof"} and not name.startswith(("LogLevel.", "EventId.")):
                names.add(name)
        for offset, value in strings.items():
            if begin <= offset < end:
                names.update(value["names"])
        return names

    entities, counts, consumed = [], Counter(), -1
    gaps = [{"path": path, "reason": "lexical_fallback_without_ast", "details": "C#: no verified overload/dispatch, generated logger methods, cross-file flow or sanitization semantics"}]
    fatal_lexical_gaps = {"csharp_unterminated_string", "csharp_unterminated_interpolation", "csharp_unterminated_attribute", "csharp_nested_string_budget_exceeded", "csharp_lexer_error"}
    gaps.extend({"path": path, "reason": reason, **({"source_analysis_unavailable": True} if reason in fatal_lexical_gaps else {})} for reason in lexical_gaps)
    for match in calls:
        if match.start() < consumed:
            continue
        receiver = re.sub(r"[\s@?]", "", match.group(1))
        leaf = receiver.rsplit(".", 1)[-1]
        if not (re.search(r"(?:^|_)(?:log|logger)$|(?:Log|Logger)$", leaf) or leaf in typed_loggers):
            continue
        end = _balanced_end(masked, match.end() - 1)
        if end is None:
            gaps.append({"path": path, "reason": "unbalanced_log_call", "line": source.count("\n", 0, match.start()) + 1, "source_analysis_unavailable": True})
            continue
        consumed = end
        parts = _lexical_arguments(masked, match.end() - 1, end)
        names, deps = names_in(match.end(), end - 1), []
        missing = ["csharp_semantics_unparsed", "csharp_one_hop_lexical_only", "csharp_cross_file_dependencies_unresolved", "runtime_reachability_and_output_access_unverified"]
        for offset, value in strings.items():
            if match.end() <= offset < end:
                missing.extend(value["gaps"])
        for name in sorted({name.split(".")[0] for name in names}):
            found = definition(name, match.start())
            if found:
                begin, value_start, finish, _ = found
                deps.append({"path": path, "symbol": name, "start_line": source.count("\n", 0, begin) + 1,
                             "end_line": source.count("\n", 0, finish) + 1, "code": source[begin:finish], "kind": "argument_definition"})
                names.update(names_in(value_start, finish))
                for offset, value in strings.items():
                    if value_start <= offset < finish:
                        missing.extend(value["gaps"])
        message_index = next((index for index, part in enumerate(parts) if literal(part)), None)
        message_literal = literal(parts[message_index]) if message_index is not None else None
        message = message_literal["body"] if message_literal else "<dynamic>"
        if message_literal is None:
            missing.append("csharp_dynamic_message_template_unresolved")
        if message_literal and not message_literal["interpolated"]:
            placeholders = re.findall(r"(?<!\{)\{[@$]?([A-Za-z_]\w*)(?:,[^{}:]+)?(?::[^{}]+)?\}(?!\})", message)
            for index, field in enumerate(placeholders, message_index + 1):
                if index >= len(parts):
                    missing.append("csharp_template_argument_missing")
                    continue
                argument = literal(parts[index])
                if not (argument and not argument["interpolated"] and MASKED.fullmatch(argument["body"])):
                    names.add(field)
        template = hashlib.sha256(message.encode()).hexdigest()[:16]
        ordinal = counts[template]
        counts[template] += 1
        statement, callee = source[match.start():end], receiver + "." + match.group(2)
        caught = {name for name, begin, finish in exception_bindings if begin <= match.start() < finish}
        value_types = {name: _types(name) | ({"exception_data"} if name.split(".")[0] in caught else set()) for name in names}
        entities.append(annotate_entity({"path": path, "symbol": "<lexical_scope_unknown>", "callee": callee, "level": match.group(2).lower(),
            "start_line": source.count("\n", 0, match.start()) + 1, "end_line": source.count("\n", 0, end) + 1,
            "statement": statement, "semantic_statement": statement.strip(), "identity": f"<lexical_scope_unknown>:{template}:{ordinal}",
            "message_template": message, "parser_status": "lexical_only", "log_detection_status": "possible", "dependencies": deps,
            "data_types": sorted(set().union(*value_types.values())) if names else [], "privacy_assessment": "possible" if any(value_types.values()) else "unknown",
            "source_to_sink": [{"source": name, "basis": "lexical_identifier_only", "sink": callee, "types": sorted(value_types[name])} for name in sorted(names)],
            "existing_sanitization": [], "trigger_conditions": ["requires_logger_level:" + match.group(2).lower(), "lexical_trigger_conditions_unresolved"],
            "matched_rules": ["balanced_multiline_csharp_lexical_sink"], "missing_evidence": sorted(set(missing)),
            "analysis_depth": 1, "analysis_method": "bounded_lexical", "reverse_dependency_coverage": "partial"}))
    return entities, gaps


def _lexical_entities(path: str, source: str, files: dict[str, str]) -> tuple[list[dict], list[dict]]:
    masked = _mask_lexical(source, LANGUAGES.get(posixpath.splitext(path)[1].lower(), "python"))
    regex = re.compile(r"\b((?:(?:[A-Za-z_$][\w$]*\.)*(?:logger|log|logging|console))\s*\.\s*(?:debug|info|warning|warn|error|exception|critical|fatal|trace|log)|print)\s*\(", re.I)
    entities, gaps = [], [{"path": path, "reason": "lexical_fallback_without_ast", "details": "No precise alias/type/value-flow or dynamic dispatch resolution"}]
    declarations = {}
    for declaration in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=", masked):
        tail = declaration.end()
        end = masked.find(";", tail)
        if end < 0:
            end = masked.find("\n", tail)
        end = len(source) if end < 0 else end + 1
        declarations[declaration.group(1)] = (declaration.start(), end)
    counts: Counter = Counter()
    for match in regex.finditer(masked):
        end = _balanced_end(masked, match.end() - 1)
        if end is None:
            gaps.append({"path": path, "reason": "unbalanced_log_call", "line": source.count("\n", 0, match.start()) + 1})
            continue
        statement = source[match.start():end]
        start_line = source.count("\n", 0, match.start()) + 1
        end_line = source.count("\n", 0, end) + 1
        callee = re.sub(r"\s", "", match.group(1))
        level = callee.rsplit(".", 1)[-1] if "." in callee else "stdout"
        deps, types = [], set()
        arguments = statement[statement.find("(") + 1:]
        names = set(re.findall(r"\b[A-Za-z_$][\w$]*\b", masked[match.end():end - 1]))
        for name in sorted(names):
            types.update(_types(name))
            declaration = declarations.get(name)
            if declaration and declaration[0] < match.start():
                begin, finish = declaration
                code = source[begin:finish]
                deps.append({"path": path, "symbol": name, "start_line": source.count("\n", 0, begin) + 1, "end_line": source.count("\n", 0, finish) + 1, "code": code, "kind": "argument_definition"})
                for ident in re.findall(r"\b[A-Za-z_$][\w$]*\b", code):
                    types.update(_types(ident))
        for field_name in re.findall(r"[\"']([^\"']+)[\"']\s*:", arguments):
            types.update(_types(field_name))
        message = next(iter(re.findall(r"[\"']([^\"'\n]*)[\"']", arguments)), "<dynamic>")
        template = hashlib.sha256(message.encode()).hexdigest()[:16]
        ordinal = counts[template]
        counts[template] += 1
        entities.append({"path": path, "symbol": "<lexical_scope_unknown>", "callee": callee, "level": level, "start_line": start_line, "end_line": end_line, "statement": statement, "identity": f"<lexical_scope_unknown>:{template}:{ordinal}", "message_template": message, "parser_status": "lexical_only", "log_detection_status": "possible", "dependencies": deps, "data_types": sorted(types), "privacy_assessment": "possible" if types else "unknown", "source_to_sink": [{"source": name, "basis": "lexical_identifier_only", "sink": callee, "types": sorted(_types(name))} for name in sorted(names) if _types(name)], "existing_sanitization": [], "trigger_conditions": ["requires_logger_level:" + level, "lexical_trigger_conditions_unresolved"], "matched_rules": ["balanced_multiline_lexical_sink"], "missing_evidence": ["js_ts_semantics_unparsed", "runtime_reachability_and_output_access_unverified"], "analysis_depth": 1, "analysis_method": "bounded_lexical", "reverse_dependency_coverage": "partial"})
        entities[-1]["semantic_statement"] = statement.strip()
    return [annotate_entity(entity) for entity in entities], gaps


def detect_snapshot(files: dict[str, str], languages: list[str] | None = None) -> dict:
    """Return every confirmed/possible log, including privacy-negative entities.

    ``files`` must contain historical text supplied by the miner, never a live
    checkout substitution. One-hop import resolution uses this snapshot only.
    """
    selected_languages = {language.lower() for language in (languages or ["python", "javascript", "typescript", "go", "csharp"])}
    selected = {path: source for path, source in files.items() if LANGUAGES.get(posixpath.splitext(path)[1].lower()) in selected_languages}
    index = PythonSnapshot(selected)
    entities, gaps = index.entities(), list(index.gaps)
    for path, source in sorted(selected.items()):
        if path not in index.trees:
            extension = posixpath.splitext(path)[1].lower()
            found, lexical_gaps = _go_entities(path, source) if extension == ".go" else _csharp_entities(path, source) if extension == ".cs" else _lexical_entities(path, source, selected)
            entities.extend(found)
            gaps.extend(lexical_gaps)
    return {"entities": sorted(entities, key=lambda e: (e["path"], e["start_line"], e["identity"])), "gaps": gaps}


def match_entities(before: list[dict], after: list[dict], old_path: str | None = None, new_path: str | None = None) -> list[dict]:
    """Compatibility entrypoint for the shared conservative matcher."""
    from .matching import match_entities as match
    return match(before, after, old_path, new_path)
