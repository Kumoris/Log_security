"""Synthetic fixtures only; no sealed or real repository sources."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from execute_swechat_followups import match_anchor

def fixture():
    c=dict(commit_sha='a'*40,path='src/app.py',start_line='4',end_line='4',statement="print('x')")
    e=dict(sha='a'*40,after=dict(path='src/app.py',start_line=4,end_line=4,statement="print('x')"))
    return c,e

def test_anchor_requires_exact_commit_path_and_lines():
    import copy
    c,e=fixture();assert match_anchor(c,e)
    wrong=copy.deepcopy(e);wrong['sha']='b'*40;assert not match_anchor(c,wrong)
    for key,value in [('path','other/app.py'),('start_line',5),('end_line',5)]:
        wrong=copy.deepcopy(e);wrong['after'][key]=value;assert not match_anchor(c,wrong)

def test_anchor_does_not_use_keyword_similarity_or_before_only():
    c,e=fixture();e['after']['statement']="print('x changed')";assert not match_anchor(c,e)
    c,e=fixture();e['before']=e.pop('after');assert not match_anchor(c,e)

def test_exact_call_inside_same_source_statement_can_map():
    c,e=fixture();e['after']['statement']="value = print('x')";assert match_anchor(c,e)

def test_windows_native_path_is_not_a_git_relative_path():
    c,e=fixture();e['after']['path']='src\\app.py';assert not match_anchor(c,e)
    e['after']['path']=e['after']['path'].replace('\\','/');assert match_anchor(c,e)


def test_nested_call_must_preserve_callee():
    c,e=fixture();c['callee']='print';e['after']['callee']='logger.info'
    e['after']['statement']="logger.info(print('x'))"
    assert not match_anchor(c,e)
