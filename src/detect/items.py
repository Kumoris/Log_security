"""What a log call outputs: its message template and one LogItem per output value.

  f"a {x} b {y}"             -> x, y
  "a %s %s", x, y            -> x, y           (also "a %s" % x, "a %(k)s" % {"k": x})
  "a {} {k}".format(x, k=y)  -> x, y(key=k)
  extra={"uid": x}, uid=x    -> x(key=uid)     (structlog / loguru keyword fields)
  exc_info=True, .exception  -> exception item
  print(a, b)                -> a, b

Wrapping calls and slices are peeled off into ``wrappers`` so that ``mask(token)``
and ``token[:6]`` keep ``core == "token"``.
"""
from __future__ import annotations

import ast

from ..models import LogItem

_SKIP_KWARGS = frozenset({"stacklevel", "sep", "end", "file", "flush"})
_EXC_KWARGS = frozenset({"exc_info", "stack_info"})


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def peel(node: ast.AST) -> tuple[ast.AST, tuple[str, ...]]:
    """Strip single-argument wrapping calls and slices: mask(str(x))[:6] -> (x, (slice, mask, str))."""
    wrappers = []
    for _ in range(6):
        if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords:
            name = _dotted(node.func)
            if name is None:
                break
            wrappers.append(name)
            node = node.args[0]
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            wrappers.append("slice")
            node = node.value
        else:
            break
    return node, tuple(wrappers)


def make_item(node: ast.AST, key: str | None = None, role: str = "value") -> LogItem:
    core, wrappers = peel(node)
    return LogItem(expr=ast.unparse(node), core=ast.unparse(core), wrappers=wrappers, key=key, role=role)


def _is_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _decompose(node: ast.AST) -> list[LogItem]:
    """Items inside one message-like argument."""
    if isinstance(node, ast.Constant):
        return []
    if isinstance(node, ast.JoinedStr):
        return [make_item(v.value) for v in node.values if isinstance(v, ast.FormattedValue)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _is_str(node.left):
        right = node.right
        if isinstance(right, ast.Tuple):
            return [make_item(e) for e in right.elts]
        if isinstance(right, ast.Dict):
            return [make_item(v, key=k.value if _is_str(k) else None) for k, v in zip(right.keys, right.values)]
        return [make_item(right)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _decompose(node.left) + _decompose(node.right)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
            and _is_str(node.func.value)):
        return [make_item(a) for a in node.args] + [make_item(k.value, key=k.arg) for k in node.keywords]
    return [make_item(node)]


def _message_args(node: ast.Call, method: str, sink: str) -> list[ast.AST]:
    args = list(node.args)
    if sink == "logger" and method == "log" and args:
        args = args[1:]                                     # level argument
    return args


def extract_items(node: ast.Call, method: str, sink: str) -> tuple[LogItem, ...]:
    args = _message_args(node, method, sink)
    items: list[LogItem] = []
    if sink == "print":
        for a in args:
            items += _decompose(a)
    elif args:
        items += _decompose(args[0])
        items += [make_item(a) for a in args[1:]]           # %-style positional values
    exc = sink == "logger" and method == "exception"
    for k in node.keywords:
        if k.arg in _SKIP_KWARGS:
            continue
        if k.arg in _EXC_KWARGS:
            if not (isinstance(k.value, ast.Constant) and not k.value.value):
                exc = True
            continue
        if k.arg == "extra" and isinstance(k.value, ast.Dict):
            items += [make_item(v, key=kk.value if _is_str(kk) else None) for kk, v in zip(k.value.keys, k.value.values)]
        else:
            items.append(make_item(k.value, key=k.arg))
    if exc:
        items.append(LogItem(expr="<exc_info>", core="<exc_info>", role="exception"))
    return tuple(items)


def template_of(node: ast.Call, method: str) -> str:
    args = _message_args(node, method, "logger" if method != "print" else "print")
    if not args:
        return ""
    a = args[0]
    if _is_str(a):
        return a.value
    if isinstance(a, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in a.values)
    if isinstance(a, ast.BinOp) and isinstance(a.op, ast.Mod) and _is_str(a.left):
        return a.left.value
    if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr == "format" and _is_str(a.func.value):
        return a.func.value.value
    return ""
