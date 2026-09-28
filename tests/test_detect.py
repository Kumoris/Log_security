import textwrap
from datetime import datetime, timezone

import pytest

from src.detect.match import match_file
from src.detect.python_ast import find_logs
from src.models import ChangeKind, CommitWork, FileVersions, SensLevel
from src.repo.analyze import analyze_commit


def src(s):
    return textwrap.dedent(s).lstrip()


def logs(s, path="m.py"):
    return find_logs(path, src(s)).statements


# ------------------------------------------------------------------ finding logs

def test_logger_propagation_and_levels():
    st = logs("""
        import logging
        log = logging.getLogger(__name__)
        child = log.getChild("x")
        class S:
            def __init__(self):
                self.lg = child
            def run(self, n):
                self.lg.info("run %s", n)
                logging.warning("w")
                child.debug("d")
                math.log(3)
    """)
    assert [s.method for s in st] == ["info", "warning", "debug"]
    assert all(s.detection == "tracked" for s in st)
    assert st[0].scope == "S.run"


def test_loguru_structlog_heuristic_and_wrapper():
    st = logs("""
        from loguru import logger
        import structlog
        slog = structlog.get_logger().bind(svc="a")
        def emit(msg):
            logger.info(msg)
        def f(u):
            logger.success("ok")
            slog.info("x", user=u)
            LOGGER.error("named only")
            emit(u.email)
    """)
    det = {(s.method, s.detection) for s in st}
    assert ("success", "tracked") in det
    assert ("info", "tracked") in det
    assert ("error", "name_heuristic") in det
    assert ("emit", "wrapper") in det


def test_formatting_does_not_change_fingerprint():
    a = logs("""
        import logging
        log = logging.getLogger()
        def f(x):
            log.info("v=%s", x)
    """)
    b = logs("""
        import logging
        log = logging.getLogger()


        def f(x):
            # comment
            log.info(
                "v=%s",   x,
            )
    """)
    assert a[0].fingerprint == b[0].fingerprint


def test_duplicate_statements_get_occurrence():
    st = logs("""
        import logging
        log = logging.getLogger()
        def f():
            log.info("done")
            log.info("done")
    """)
    assert [s.occurrence for s in st] == [0, 1]
    assert st[0].fingerprint != st[1].fingerprint
    assert st[0].group_size == 2


def test_syntax_error_raises():
    with pytest.raises(SyntaxError):
        find_logs("x.py", "print 'py2'\n")


# ------------------------------------------------------------------ sensitivity (agentlog_unified's own judgement)

from src.reference.detector import detect_snapshot


def sens(body, extra=""):
    st = logs("import logging\nlog = logging.getLogger()\n" + extra + body)
    return st[-1].sensitivity


def ref_assessment(src_text, line):
    ents = detect_snapshot({"m.py": src_text}, ["python"])["entities"]
    return next(e["privacy_assessment"] for e in ents if e["start_line"] == line)


def test_matches_reference_detector_exactly():
    code = src("""
        import logging
        from pydantic import BaseModel, EmailStr
        log = logging.getLogger()
        class User(BaseModel):
            email: EmailStr
        def f(u: User, password, token_count, request):
            log.info("a %s", u.email)
            log.info("b %s", password)
            log.info("c %d", token_count)
            log.info("d %s", request.body)
            log.info("started")
            print("done", len(password))
    """)
    for st in find_logs("m.py", code).statements:
        assert st.sensitivity.reference_found
        assert st.sensitivity.level.value == ref_assessment(code, st.line)


def test_reference_levels():
    extra = "from pydantic import BaseModel, EmailStr\nclass User(BaseModel):\n    email: EmailStr\n"
    assert sens("def f(u: User):\n    log.info('%s', u.email)\n", extra).level == SensLevel.SUPPORTED
    assert sens("def f(password):\n    log.info('%s', password)\n").level == SensLevel.POSSIBLE
    assert sens("log.info('started')\n").level == SensLevel.NOT_SUPPORTED
    s = sens("def f(email):\n    log.info('%s', email)\n")
    assert s.level == SensLevel.POSSIBLE and s.data_types


def test_print_counts_by_default():
    st = logs("def f(password):\n    print('pw', password)\n")
    assert st and st[0].method == "print" and st[0].sensitivity.level == SensLevel.POSSIBLE


# ------------------------------------------------------------------ matching

def pf(s, path="m.py"):
    return find_logs(path, src(s))


BASE = """
import logging
from pydantic import BaseModel, EmailStr
log = logging.getLogger()
class User(BaseModel):
    email: EmailStr
def login(user: User):
    log.info("login %s", user.email)
    log.debug("done")
"""


def test_removing_supported_field_is_a_repair():
    """agentlog_unified change_labels: supported flow removed and nothing sensitive left."""
    b = pf(BASE)
    a = pf(BASE.replace('log.info("login %s", user.email)', 'log.info("login ok")'))
    ps = match_file(list(b.statements), list(a.statements), renamed=False, file_deleted=False, after_scopes=a.scopes)
    (p,) = ps
    assert p.change == ChangeKind.MODIFIED and p.confidence == "exact"
    assert "remove_sensitive_field" in p.labels and p.fix_effect == "eliminates_observed_flow"


def test_wrapping_in_mask_is_not_a_repair_in_reference_logic():
    b = pf(BASE)
    a = pf(BASE.replace("user.email)", "mask(user.email))"))
    (p,) = match_file(list(b.statements), list(a.statements), renamed=False, file_deleted=False, after_scopes=a.scopes)
    assert p.fix_effect not in ("eliminates_observed_flow", "partial")


def test_multiple_changes_in_scope_are_ambiguous():
    b = pf(BASE)
    a = pf(BASE.replace('"login %s", user.email', '"login %s", user.name').replace('log.debug("done")', 'log.debug("done %s", 1)\n    log.info("new")'))
    ps = match_file(list(b.statements), list(a.statements), renamed=False, file_deleted=False, after_scopes=a.scopes)
    assert all(p.confidence != "exact" or p.change == ChangeKind.ADDED for p in ps if p.change == ChangeKind.MODIFIED)
    assert any(p.confidence == "ambiguous" for p in ps)


def test_function_rename_is_move_not_delete():
    b = pf(BASE)
    a = pf(BASE.replace("def login", "def sign_in"))
    ps = match_file(list(b.statements), list(a.statements), renamed=False, file_deleted=False, after_scopes=a.scopes)
    assert {p.change for p in ps} == {ChangeKind.MOVED}
    assert all(p.confidence == "exact" for p in ps)


def test_scope_removed_is_probable():
    b = pf(BASE)
    a = pf("import logging\nfrom pydantic import BaseModel, EmailStr\nlog = logging.getLogger()\n")
    ps = match_file(list(b.statements), list(a.statements), renamed=False, file_deleted=False, after_scopes=a.scopes)
    assert {p.change for p in ps} == {ChangeKind.SCOPE_REMOVED}
    assert all(p.confidence == "probable" for p in ps)


def test_duplicate_shift_is_ambiguous():
    b = pf("import logging\nlog = logging.getLogger()\ndef f():\n    log.info('done')\n")
    a = pf("import logging\nlog = logging.getLogger()\ndef f():\n    log.info('done')\n    log.info('done')\n")
    ps = match_file(list(b.statements), list(a.statements), renamed=False, file_deleted=False, after_scopes=a.scopes)
    assert ps and all(p.confidence == "ambiguous" for p in ps)


def _work(files, msg="m"):
    return CommitWork("o/r", "c" * 40, ("p" * 40,), datetime(2026, 1, 1, tzinfo=timezone.utc), "a@b", msg, False, tuple(files))


def test_analyze_commit_rename_and_cross_file_and_parse_gap():
    s = src(BASE)
    ev, gaps = analyze_commit(_work([FileVersions("new.py", "old.py", 100, s, s)]))
    assert [e.change for e in ev] == [ChangeKind.MOVED, ChangeKind.MOVED]
    assert all(e.before_fp != e.after_fp for e in ev)

    ev, gaps = analyze_commit(_work([FileVersions("a.py", None, None, s, None),
                                     FileVersions("b.py", None, None, None, s)]))
    assert {e.change for e in ev} == {ChangeKind.MOVED}
    assert all("cross_file" in e.labels for e in ev)

    ev, gaps = analyze_commit(_work([FileVersions("a.py", None, None, s, "def (:\n")]))
    assert ev == [] and gaps[0].kind == "parse_failed" and gaps[0].side == "after"


def test_repair_event_is_privacy_fix():
    b = src(BASE)
    ev, _ = analyze_commit(_work([FileVersions("m.py", None, None, b, b.replace('log.info("login %s", user.email)', 'log.info("login ok")'))]))
    assert ev[0].is_privacy_fix


def test_field_swap_is_not_a_fix():
    b = pf("import logging\nlog = logging.getLogger()\ndef f(session_id, uid):\n    log.info('s=%s', session_id)\n")
    a = pf("import logging\nlog = logging.getLogger()\ndef f(session_id, uid):\n    log.info('u=%s', uid)\n")
    (p,) = match_file(list(b.statements), list(a.statements), renamed=False, file_deleted=False, after_scopes=a.scopes)
    assert p.fix_effect not in ("eliminates_observed_flow", "partial")


def test_helper_forwarding_param_is_not_wrapper():
    st = logs("""
        import logging
        log = logging.getLogger()
        def cancel(order):
            log.info("cancel %s", order)
            api.cancel(order)
        def f(o):
            cancel(o)
    """)
    assert [s.detection for s in st] == ["tracked"]
