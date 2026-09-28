"""Python log statement discovery. Pure: source text in, statements out.

Three steps:
  1. find which variables are loggers, propagating a few rounds
     (``log = logging.getLogger(__name__)``, ``log = parent.getChild("x")``,
     ``log = logger.bind(user=1)``, ``self.log = log``)
  2. find method calls on those variables whose method is a level name
  3. wrapper functions (``def log_event(msg): logger.info(msg)``) are sinks too

Receivers that were not traced but are *named* like a logger (``LOGGER.info``,
``self._log.warning``) are kept with ``detection="name_heuristic"``. ``print`` is a
sink unless disabled. Each statement carries its output items (see items.py).
"""
from __future__ import annotations

import ast
import hashlib
import re
import warnings
from functools import lru_cache

from ..models import LogStatement, ParsedFile
from .items import extract_items, template_of

LEVELS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical",
                    "fatal", "log", "trace", "success", "msg"})
FACTORIES = frozenset({"getLogger", "get_logger", "getChild", "LoggerAdapter", "bind", "opt",
                       "new", "child", "with_name", "patch", "wrap_logger", "get_task_logger",
                       "getLoggerClass"})
LOGGING_MODULES = frozenset({"logging", "structlog", "loguru", "logbook", "celery.utils.log"})
_LOGGER_NAME = re.compile(r"^_*(?:log|logger|logs|_log|lg|log_\w+|\w+_log|\w*logger)$", re.I)
# a wrapper must look like one: logging-ish name, or a tiny body that is essentially the log call
_WRAPPER_NAME = re.compile(r"(?:^|_)(?:log|logs|logger|logging|audit|emit|trace|debug|info|warn|warning|error|notify)(?:$|_)", re.I)
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_COND_NODES = (ast.If, ast.While)


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def structure_hash(node: ast.AST) -> str:
    """Formatting-insensitive: whitespace and line moves do not matter, arguments do."""
    return hashlib.sha1(ast.dump(node, include_attributes=False).encode()).hexdigest()[:16]


class _Scopes(ast.NodeVisitor):
    """Qualified names for every node (Cls.method, outer.<locals>.inner, <module>) and parents."""

    def __init__(self):
        self.stack: list[str] = []
        self.kinds: list[str] = []
        self.scope_of: dict[ast.AST, str] = {}
        self.scope_node: dict[str, ast.AST] = {}
        self.parents: dict[ast.AST, ast.AST] = {}

    def qual(self) -> str:
        return ".".join(self.stack) or "<module>"

    def generic_visit(self, node):
        self.scope_of[node] = self.qual()
        for child in ast.iter_child_nodes(node):
            self.parents[child] = node
            if isinstance(child, _SCOPE_NODES):
                prefix = ["<locals>"] if self.kinds and self.kinds[-1] == "func" else []
                self.stack += prefix + [child.name]
                self.kinds.append("class" if isinstance(child, ast.ClassDef) else "func")
                name = self.qual()
                self.scope_node.setdefault(name, child)
                self.scope_of[child] = name
                self.generic_visit(child)
                self.kinds.pop()
                del self.stack[len(self.stack) - len(prefix) - 1:]
            else:
                self.visit(child)


class _LoggerFinder:
    def __init__(self, tree: ast.Module):
        self.loggers: set[str] = set()
        self.module_aliases: set[str] = set()
        self.factory_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name in LOGGING_MODULES or a.name.split(".")[0] in {"logging", "structlog", "loguru"}:
                        self.module_aliases.add(a.asname or a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                for a in node.names:
                    bound = a.asname or a.name
                    if root == "loguru" and a.name == "logger":
                        self.loggers.add(bound)
                    elif root in {"logging", "structlog", "logbook"} or node.module in LOGGING_MODULES:
                        if a.name in FACTORIES:
                            self.factory_names.add(bound)
                    elif a.name in {"logger", "log", "LOGGER", "LOG"}:
                        self.loggers.add(bound)
        assigns = [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None]
        for _ in range(4):
            before = len(self.loggers)
            for a in assigns:
                if self.is_logger_expr(a.value):
                    for t in (a.targets if isinstance(a, ast.Assign) else [a.target]):
                        d = _dotted(t)
                        if d:
                            self.loggers.add(d)
            if len(self.loggers) == before:
                break

    def is_logger_expr(self, node: ast.AST) -> bool:
        d = _dotted(node)
        if d is not None:
            return d in self.loggers
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                return f.id in self.factory_names or f.id in ("getLogger", "get_logger")
            if isinstance(f, ast.Attribute) and f.attr in FACTORIES:
                base = _dotted(f.value)
                if base in self.module_aliases or base in self.loggers:
                    return True
                if f.attr in ("getLogger", "get_logger", "get_task_logger"):
                    return True
                return self.is_logger_expr(f.value)
        return False

    def classify_receiver(self, recv: ast.AST) -> str | None:
        d = _dotted(recv)
        if d is not None and d in self.module_aliases:
            return "tracked"
        if self.is_logger_expr(recv):
            return "tracked"
        last = d.rsplit(".", 1)[-1] if d else None
        if last and _LOGGER_NAME.match(last):
            return "name_heuristic"
        return None


def _looks_like_wrapper(fn) -> bool:
    body = [st for st in fn.body if not (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant))]
    only_log = len(body) == 1 and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Call)
    return bool(_WRAPPER_NAME.search(fn.name.lstrip("_"))) or only_log


def _code(source_lines: list[str], node: ast.AST) -> str:
    start, end = node.lineno, getattr(node, "end_lineno", node.lineno) or node.lineno
    text = "\n".join(source_lines[start - 1:end])
    return text if len(text) <= 2000 else text[:2000] + "…"


def _conditions(node: ast.AST, parents: dict) -> tuple[str, ...]:
    out, child, cur = [], node, parents.get(node)
    while cur is not None and not isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
        if isinstance(cur, _COND_NODES) and child is not cur.test:
            test = ast.unparse(cur.test)
            out.append(("not (" + test + ")") if isinstance(cur, ast.If) and child in cur.orelse else test)
        child, cur = cur, parents.get(cur)
    return tuple(reversed(out))


@lru_cache(maxsize=512)
def find_logs(path: str, source: str, include_print: bool = True) -> ParsedFile:
    """Parse one file version. Raises SyntaxError / ValueError / RecursionError on bad input."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source, filename=path, type_comments=False)
    scopes = _Scopes()
    scopes.visit(tree)
    finder = _LoggerFinder(tree)
    source_lines = source.splitlines()

    sinks: list[tuple[ast.Call, str, str, str, str]] = []    # node, receiver, method, sink, detection
    wrappers: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in LEVELS:
            detection = finder.classify_receiver(f.value)
            if detection is None:
                continue
            sinks.append((node, _dotted(f.value) or "<expr>", f.attr, "logger", detection))
            scope_name = scopes.scope_of.get(node, "<module>")
            fn = scopes.scope_node.get(scope_name)
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and not fn.name.startswith("__") \
                    and _looks_like_wrapper(fn):
                params = {a.arg for a in fn.args.args + fn.args.kwonlyargs} - {"self", "cls"}
                used = {n.id for a in list(node.args) + [k.value for k in node.keywords]
                        for n in ast.walk(a) if isinstance(n, ast.Name)}
                if params & used:
                    wrappers[fn.name] = scope_name
        elif include_print and isinstance(f, ast.Name) and f.id == "print":
            sinks.append((node, "print", "print", "print", "print"))

    if wrappers:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = f.id if isinstance(f, ast.Name) else (
                f.attr if isinstance(f, ast.Attribute) and _dotted(f.value) in ("self", "cls") else None)
            if name in wrappers and not scopes.scope_of.get(node, "").startswith(wrappers[name]):
                sinks.append((node, f"<wrapper:{name}>", name, "wrapper", "wrapper"))

    sinks.sort(key=lambda s: (s[0].lineno, s[0].col_offset))
    statements = []
    for node, receiver, method, sink, detection in sinks:
        statements.append(LogStatement(
            path=path, scope=scopes.scope_of.get(node, "<module>"), line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno) or node.lineno, col=node.col_offset,
            code=_code(source_lines, node), receiver=receiver, method=method, sink=sink, detection=detection,
            template=template_of(node, method), items=extract_items(node, method, sink),
            conditions=_conditions(node, scopes.parents), shash=structure_hash(node)))
    return ParsedFile(path=path, statements=tuple(statements))
