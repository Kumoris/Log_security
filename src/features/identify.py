"""Explicit privacy features of each output item (stage 4). Facts with evidence, no verdict.

For every item of a log statement version:
  name            the identifier / access path matches the dictionary (taxonomy.py)
  field_key       the extra={...} / keyword field name matches
  access          header / cookie / environment subscripts, whole request / response / settings objects
  type            a type annotation (parameter, local, model field) that is itself a privacy type
  source_call     the value was assigned from a known source call (LLM client, HTTP client,
                  environment, file read, request body, traceback)
  name_via_definition  the right-hand side of the value's last assignment matches the dictionary
  exception       exc_info / logger.exception / a name bound by ``except ... as e``
  literal         a hard-coded secret in the message text or a constant argument
Value tracing is deliberately bounded: the enclosing function's last assignment, parameters,
``self.attr`` assignments in the same class, model fields in the same file, three hops at most.
Items with no evidence are *unclassified*, never "safe".
"""
from __future__ import annotations

import ast
import re
import warnings
from functools import lru_cache

from ..models import LogItem, LogStatement
from .taxonomy import CARRIERS, CATEGORIES, match_identifier

TYPE_HINTS = {
    "EmailStr": ("PII", "email", "邮箱"), "NameEmail": ("PII", "email", "邮箱"),
    "SecretStr": ("AUTH", "credential_bundle", "其他认证秘密或凭证对象"),
    "SecretBytes": ("AUTH", "credential_bundle", "其他认证秘密或凭证对象"),
    "PaymentCardNumber": ("PII", "financial", "个人金融信息"),
    "IPvAnyAddress": ("QID", "network_identifier", "网络关联标识"),
    "IPv4Address": ("QID", "network_identifier", "网络关联标识"),
    "IPv6Address": ("QID", "network_identifier", "网络关联标识"),
    "PhoneNumber": ("PII", "phone", "电话"),
}
LLM_CALL = re.compile(r"(?:chat\.completions\.create|\bcompletions\.create|messages\.create|responses\.create|"
                      r"generate_content|ChatCompletion\.create|litellm\.a?completion|\ba?completion\b|"
                      r"\.a?invoke\b|\.a?predict\b|\.a?generate\b|\.a?chat\b)$")
HTTP_CALL = re.compile(r"(?:^|\.)(?:requests|httpx|session|client|aiohttp)\.(?:get|post|put|patch|delete|request|head)$"
                       r"|urlopen$|\.fetch$")
ENV_CALL = re.compile(r"(?:^|\.)(?:os\.getenv|getenv|os\.environ\.get|environ\.get)$")
FILE_READ = re.compile(r"(?:\.read|\.read_text|\.read_bytes|\.readlines|json\.load|yaml\.safe_load|yaml\.load)$")
TRACEBACK = re.compile(r"traceback\.(?:format_exc|format_exception|print_exc|format_tb)$")
REQUEST_NAME = re.compile(r"^(?:req|request|flask\.request|self\.request)$", re.I)
RESPONSE_NAME = re.compile(r"^(?:r|res|resp|response|http_response|api_response|result)$", re.I)
BODY_ATTRS = {"json", "get_json", "text", "content", "body", "data", "form", "args", "values", "files", "raw"}
SETTINGS_NAMES = {"settings", "SETTINGS", "config", "CONFIG", "app.config", "conf"}
SECRET_LITERAL = re.compile(r"(?i)\b(password|passwd|secret|api_key|access_token|authorization)\s*[:=]\s*([^\s,;'\"{}%]+)")
KEY_FORMATS = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|"
                         r"xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})")
EXC_NAMES = {"e", "ex", "exc", "err"}
MASKED = re.compile(r"^(?:\*+|x+|X+|<[^>]*>|\[[^\]]*\]|redacted|masked|hidden|none|null|\.{3})$", re.I)


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return None


def _ev(cat: str, sub: str, label: str, kind: str, matched: str, legacy: str | None = None) -> dict:
    return {"category": cat, "subtype": sub, "label": label, "category_label": CATEGORIES.get(cat, cat),
            "kind": kind, "matched": matched[:200], "carrier": legacy in CARRIERS if legacy else False}


def _name_evidence(text: str, kind: str) -> list[dict]:
    return [_ev(r[0], r[1], r[2], kind, text, r[4]) for r in match_identifier(text)]


# --------------------------------------------------------------------------- file context

class FileContext:
    def __init__(self, source: str | None):
        self.tree = None
        self.fields: dict[str, dict[str, str]] = {}           # class -> field -> annotation text
        self.self_assign: dict[str, dict[str, list[ast.AST]]] = {}
        self.funcs: list[ast.AST] = []
        if not source:
            return
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                self.tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                f = self.fields.setdefault(node.name, {})
                sa = self.self_assign.setdefault(node.name, {})
                for st in node.body:
                    if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                        f[st.target.id] = ast.unparse(st.annotation)
                for sub in ast.walk(node):
                    if isinstance(sub, (ast.Assign, ast.AnnAssign)) and sub.value is not None:
                        for t in (sub.targets if isinstance(sub, ast.Assign) else [sub.target]):
                            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                                sa.setdefault(t.attr, []).append(sub.value)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs.append(node)

    def enclosing(self, line: int):
        best = None
        for fn in self.funcs:
            if fn.lineno <= line <= (fn.end_lineno or fn.lineno):
                if best is None or fn.lineno >= best.lineno:
                    best = fn
        return best

    def class_of(self, fn) -> str | None:
        if self.tree is None or fn is None:
            return None
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef) and fn in ast.walk(node):
                return node.name
        return None


@lru_cache(maxsize=256)
def file_context(source: str | None) -> FileContext:
    return FileContext(source)


def _param_annotation(fn, name: str) -> str | None:
    if fn is None:
        return None
    args = fn.args
    for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
        if a.arg == name and a.annotation is not None:
            return ast.unparse(a.annotation)
    return None


def _last_assignment(fn, name: str, line: int):
    """(rhs node, annotation text) of the last assignment to ``name`` before ``line`` in ``fn``."""
    if fn is None:
        return None, None
    best, best_line, ann = None, -1, None
    for node in ast.walk(fn):
        ln = getattr(node, "lineno", None)
        if ln is None or ln >= line:
            continue
        targets, value = [], None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        elif isinstance(node, ast.NamedExpr):
            targets, value = [node.target], node.value
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            targets, value = [node.target], node.iter
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for it in node.items:
                if it.optional_vars is not None and isinstance(it.optional_vars, ast.Name) and it.optional_vars.id == name \
                        and ln > best_line:
                    best, best_line, ann = it.context_expr, ln, None
            continue
        for t in targets:
            names = [t] if isinstance(t, ast.Name) else [e for e in getattr(t, "elts", []) if isinstance(e, ast.Name)]
            if any(n.id == name for n in names) and ln > best_line:
                best, best_line = value, ln
                ann = ast.unparse(node.annotation) if isinstance(node, ast.AnnAssign) else None
    return best, ann


def _except_names(fn, line: int) -> set[str]:
    out = set()
    if fn is None:
        return out
    for node in ast.walk(fn):
        if isinstance(node, ast.ExceptHandler) and node.name and node.body:
            end = max((getattr(b, "end_lineno", b.lineno) for b in node.body), default=node.lineno)
            if node.lineno <= line <= end:
                out.add(node.name)
    return out


def _type_evidence(annotation: str | None, matched: str) -> list[dict]:
    if not annotation:
        return []
    out = []
    for tname, (cat, sub, label) in TYPE_HINTS.items():
        if re.search(r"\b" + tname + r"\b", annotation):
            out.append(_ev(cat, sub, label, "type", f"{matched}: {annotation}"))
    return out


def _call_evidence(call: ast.Call) -> list[dict]:
    name = _dotted(call.func) or ""
    text = ast.unparse(call)[:200]
    out = []
    if LLM_CALL.search(name):
        out.append(_ev("LLM", "completion", "模型输出", "source_call", text, "llm_content"))
    if HTTP_CALL.search(name):
        out.append(_ev("BIZ", "response_body", "响应体载体", "source_call", text, "opaque_object"))
    if ENV_CALL.search(name):
        out.append(_ev("CFG", "environment", "环境变量载体", "source_call", text, "internal_configuration"))
        if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            out += _name_evidence(call.args[0].value.lower(), "source_call")
    if FILE_READ.search(name):
        out.append(_ev("BIZ", "document_content", "文档及内容载体", "source_call", text, "content_visibility_unknown"))
    if TRACEBACK.search(name):
        out.append(_ev("DIAG", "stack_trace", "堆栈载体", "source_call", text, "exception_data"))
    return out


def _access_evidence(node: ast.AST) -> list[dict]:
    """Header / cookie / environment subscripts and whole request / response / settings objects."""
    text = ast.unparse(node)[:200]
    out = []
    target = node
    key = None
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
        target, key = node.value, node.slice.value
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
          and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
        target, key = node.func.value, node.args[0].value
    tname = _dotted(target) or ""
    if key is not None:
        if re.search(r"(?:^|\.)(?:os\.)?environ$", tname):
            out.append(_ev("CFG", "environment", "环境变量载体", "access", text, "internal_configuration"))
            out += [{**e, "kind": "access"} for e in _name_evidence(key.lower(), "access")]
        else:
            # any mapping read by a constant key: user.get("email"), headers["Authorization"], row["phone"]
            out += [{**e, "kind": "access"} for e in _name_evidence(key, "access")]
        return out
    if re.search(r"(?:^|\.)(?:os\.)?environ$", tname) and not isinstance(node, ast.Call):
        out.append(_ev("CFG", "environment", "环境变量载体", "access", text, "internal_configuration"))
    if tname in SETTINGS_NAMES and isinstance(node, (ast.Name, ast.Attribute)):
        out.append(_ev("CFG", "deployment_configuration", "配置及部署载体", "access", text, "internal_configuration"))
    attr = node.func.attr if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) else (
        node.attr if isinstance(node, ast.Attribute) else None)
    recv = _dotted(node.func.value if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) else (
        node.value if isinstance(node, ast.Attribute) else node)) or ""
    if attr in BODY_ATTRS:
        if REQUEST_NAME.match(recv):
            out.append(_ev("BIZ", "request_body", "请求体载体", "access", text, "opaque_object"))
        elif RESPONSE_NAME.match(recv):
            out.append(_ev("BIZ", "response_body", "响应体载体", "access", text, "opaque_object"))
    if isinstance(node, ast.Name) and REQUEST_NAME.match(node.id):
        out.append(_ev("BIZ", "request_body", "请求体载体", "access", text, "opaque_object"))
    return out


# --------------------------------------------------------------------------- per item

def _trace(node: ast.AST, ctx: FileContext, fn, line: int, depth: int, seen: set) -> tuple[list[dict], str | None]:
    """Evidence from the value's definition (bounded), and the first definition text."""
    if depth > 3:
        return [], None
    ev, definition = [], None
    if isinstance(node, ast.Name):
        key = (id(fn), node.id, line)
        if key in seen:
            return [], None
        seen.add(key)
        rhs, ann = _last_assignment(fn, node.id, line)
        ev += _type_evidence(ann or _param_annotation(fn, node.id), node.id)
        if rhs is not None:
            definition = ast.unparse(rhs)[:300]
            ev += _rhs_evidence(rhs, ctx, fn, getattr(rhs, "lineno", line), depth, seen)
    elif isinstance(node, ast.Attribute):
        base = node.value
        if isinstance(base, ast.Name) and base.id == "self":
            cls = ctx.class_of(fn)
            for rhs in (ctx.self_assign.get(cls, {}).get(node.attr, []) if cls else [])[:3]:
                definition = definition or ast.unparse(rhs)[:300]
                owner = ctx.enclosing(getattr(rhs, "lineno", 0))
                ev += _rhs_evidence(rhs, ctx, owner, getattr(rhs, "lineno", line), depth, seen)
            if cls and node.attr in ctx.fields.get(cls, {}):
                ev += _type_evidence(ctx.fields[cls][node.attr], f"{cls}.{node.attr}")
        elif isinstance(base, ast.Name):
            ann = _param_annotation(fn, base.id) or _last_assignment(fn, base.id, line)[1]
            cls = ann.split("[")[0].split(".")[-1].strip() if ann else None
            if cls and node.attr in ctx.fields.get(cls, {}):
                ev += _type_evidence(ctx.fields[cls][node.attr], f"{cls}.{node.attr}")
            rhs, _ = _last_assignment(fn, base.id, line)
            if isinstance(rhs, ast.Call):
                ev += [e for e in _call_evidence(rhs) if e["category"] in ("LLM", "BIZ")]
    elif isinstance(node, ast.Call):
        ev += _call_evidence(node)
    return ev, definition


def _rhs_evidence(rhs: ast.AST, ctx: FileContext, fn, line: int, depth: int, seen: set) -> list[dict]:
    ev = []
    core = rhs
    while isinstance(core, ast.Await):
        core = core.value
    if isinstance(core, ast.Call):
        ev += _call_evidence(core)
        ev += _access_evidence(core)
    elif isinstance(core, (ast.Attribute, ast.Subscript, ast.Name)):
        ev += _access_evidence(core)
    text = _dotted(core) if not isinstance(core, ast.Subscript) else ast.unparse(core)
    if text:
        ev += [{**e, "kind": "name_via_definition"} for e in _name_evidence(text, "name_via_definition")]
    if isinstance(core, (ast.Name, ast.Attribute)):
        more, _ = _trace(core, ctx, fn, line, depth + 1, seen)
        ev += more
    return ev


def _names_in(node: ast.AST) -> list[str]:
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and _dotted(sub):
            out.append(_dotted(sub))
        elif isinstance(sub, ast.Name):
            out.append(sub.id)
        elif isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant):
            out.append(ast.unparse(sub))
    return list(dict.fromkeys(out))


def has_data(core: str) -> bool:
    """False for pure literal expressions such as '=' * 70 or 'error'."""
    try:
        node = ast.parse(core, mode="eval").body
    except SyntaxError:
        return True
    return any(isinstance(n, (ast.Name, ast.Attribute)) for n in ast.walk(node))


def _literal_evidence(text: str, matched_kind: str = "literal") -> list[dict]:
    out = []
    for m in SECRET_LITERAL.finditer(text):
        if not MASKED.match(m.group(2)):
            out.append(_ev("AUTH", "credential_bundle", "其他认证秘密或凭证对象", matched_kind, m.group(0), "credential"))
    for m in KEY_FORMATS.finditer(text):
        out.append(_ev("AUTH", "api_key", "服务密钥", matched_kind, m.group(0)[:12] + "…", "credential"))
    return out


def _dedupe(ev: list[dict]) -> list[dict]:
    seen, out = set(), []
    for e in ev:
        k = (e["category"], e["subtype"], e["kind"], e["matched"])
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out


def identify_item(item: LogItem, st: LogStatement, ctx: FileContext, fn) -> dict:
    ev: list[dict] = []
    definition = None
    if item.role == "exception":
        ev.append(_ev("DIAG", "stack_trace", "堆栈载体", "exception", "exc_info / logger.exception", "exception_data"))
    else:
        try:
            node = ast.parse(item.core, mode="eval").body
        except SyntaxError:
            node = None
        if node is not None:
            if isinstance(node, ast.Constant):
                if isinstance(node.value, str):
                    ev += _literal_evidence(node.value)
            else:
                if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
                    ev += _name_evidence(_dotted(node) or item.core, "name")
                else:
                    # an expression: match each name / attribute in it on its own, so that
                    # aggregates like payload_size stay excluded
                    for sub in _names_in(node):
                        ev += _name_evidence(sub, "name")
                ev += _access_evidence(node)
                if isinstance(node, ast.Name) and node.id in EXC_NAMES:
                    ev.append(_ev("DIAG", "exception_message", "异常内容载体", "name", node.id, "exception_data"))
                if isinstance(node, ast.Name) and node.id in _except_names(fn, st.line):
                    ev.append(_ev("DIAG", "exception_message", "异常内容载体", "exception",
                                  f"except ... as {node.id}", "exception_data"))
                more, definition = _trace(node, ctx, fn, st.line, 0, set())
                ev += more
        if item.key:
            ev += _name_evidence(item.key, "field_key")
    ev = _dedupe(ev)
    return {"expr": item.expr, "core": item.core, "key": item.key, "role": item.role,
            "wrappers": list(item.wrappers), "definition": definition, "evidence": ev,
            "categories": sorted({f"{e['category']}.{e['subtype']}" for e in ev})}


def identify_statement(st: LogStatement, source: str | None) -> list[dict]:
    """One row per output item (+ a message row when the text itself holds a secret)."""
    ctx = file_context(source)
    fn = ctx.enclosing(st.line) if source else None
    rows = [identify_item(i, st, ctx, fn) for i in st.items]
    lit = _literal_evidence(st.template)
    if lit:
        rows.append({"expr": "<message>", "core": "<message>", "key": None, "role": "message", "wrappers": [],
                     "definition": None, "evidence": _dedupe(lit),
                     "categories": sorted({f"{e['category']}.{e['subtype']}" for e in lit})})
    return rows
