import difflib
import unittest
import sys
from pathlib import Path

from align_swechat_agent_logs import (align_file, changed_spans, locate_entities,
                                     numstats, parse_patch, restore_parent,
                                     tool_alignment)


def patch(before, after, path="app.py", new=False):
    raw = "diff --git a/" + path + " b/" + path + "\n" + "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile="/dev/null" if new else "a/" + path, tofile="b/" + path))
    p = parse_patch(raw)[path]
    counts = (sum(op == "+" for h in p["hunks"] for op, _ in h["lines"]),
              sum(op == "-" for h in p["hunks"] for op, _ in h["lines"]))
    return p, counts


def log(source, text):
    start = source.index(text)
    return {"start": start, "end": start + len(text), "statement": text,
            "start_line": source[:start].count("\n") + 1,
            "end_line": source[:start + len(text)].count("\n") + 1,
            "callee": "logger.info", "log_detection_status": "possible", "parser_status": "synthetic"}


class AlignmentTests(unittest.TestCase):
    def test_patch_roundtrip_and_offsets(self):
        before = 'a = 1\nlogger.info("old")\nb = 2\n'
        after = 'a = 1\nlogger.info("new")\nb = 2\n'
        p, counts = patch(before, after)
        restored, blocks = restore_parent(after, p, counts)
        self.assertEqual(restored, before)
        self.assertTrue(blocks[0]["spans"])

    def test_new_file(self):
        after = 'logger.info("created")\n'
        p, counts = patch("", after, new=True)
        self.assertEqual(restore_parent(after, p, counts)[0], "")
        self.assertEqual(tool_alignment({"content": after}, "", after, 0, 22, True)["status"], "exact_write_new_file_supported")

    def test_reject_wrong_postimage(self):
        p, counts = patch('x=1\n', 'x=2\n')
        with self.assertRaisesRegex(ValueError, "postimage"):
            restore_parent('x=3\n', p, counts)

    def test_reject_truncated_or_incomplete_patch(self):
        p, counts = patch('x=1\n', 'x=2\n')
        with self.assertRaisesRegex(ValueError, "numstat"):
            restore_parent('x=2\n', p, (2, 1))
        p['hunks'][0]['lines'].pop()
        raw='diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x=1\n'
        self.assertIn('hunk_count_mismatch', parse_patch(raw)['a.py']['errors'])

    def test_exact_edit_in_mixed_file(self):
        before = 'x=1\nlogger.info("old")\n'
        after = 'x=2\nlogger.info("new")\n'
        p, counts = patch(before, after)
        _, blocks = restore_parent(after, p, counts)
        tools = [{"payload": {"old_string": 'logger.info("old")', "new_string": 'logger.info("new")'}, "reference": {"source_row": 1, "tool_index_0based": 0}}]
        result = align_file(before, after, blocks, [log(before, 'logger.info("old")')], [log(after, 'logger.info("new")')], tools)
        self.assertEqual(result[0]['attribution_grade'], 'exact_tool_change_supported')
        self.assertEqual(result[0]['change_kind'], 'modified')

    def test_unchanged_log_in_edited_context_not_attributed(self):
        old='x=1\nlogger.info("same")\n'
        new='x=2\nlogger.info("same")\n'
        e=log(new,'logger.info("same")')
        result=tool_alignment({'old_string':old,'new_string':new}, old, new, e['start'],e['end'])
        self.assertEqual(result['status'],'log_only_in_unchanged_tool_context')

    def test_same_line_nonlog_change_excluded(self):
        before='x=1; logger.info("same")\n'
        after='x=2; logger.info("same")\n'
        p,counts=patch(before,after)
        _,blocks=restore_parent(after,p,counts)
        self.assertEqual(align_file(before,after,blocks,[],[log(after,'logger.info("same")')],[]),[])

    def test_multiline_argument_modification(self):
        before='logger.info(\n "value",\n old_value\n)\n'
        after='logger.info(\n "value",\n new_value\n)\n'
        p,counts=patch(before,after)
        _,blocks=restore_parent(after,p,counts)
        tools=[{'payload':{'old_string':'old_value','new_string':'new_value'},'reference':{}}]
        result=align_file(before,after,blocks,[log(before,before.strip())],[log(after,after.strip())],tools)
        self.assertEqual(result[0]['attribution_grade'],'exact_tool_change_supported')

    def test_deleted_argument_still_changes_surviving_log(self):
        before='logger.info(\n "value",\n extra=x,\n)\n'
        after='logger.info(\n "value",\n)\n'
        p,counts=patch(before,after)
        _,blocks=restore_parent(after,p,counts)
        self.assertEqual(len(align_file(before,after,blocks,[log(before,before.strip())],[log(after,after.strip())],[])),1)

    def test_repeated_postimage_is_not_strong(self):
        result=tool_alignment({'old_string':'old','new_string':'new'}, 'old', 'new;new',0,3)
        self.assertEqual(result['status'],'ambiguous_or_missing_postimage')

    def test_tool_edit_not_preserved(self):
        self.assertEqual(tool_alignment({'old_string':'old','new_string':'agent'},'old','human',0,5)['status'],'ambiguous_or_missing_postimage')

    def test_intermediate_preimage_is_lower_grade(self):
        self.assertEqual(tool_alignment({'old_string':'intermediate','new_string':'final'},'initial','final',0,5)['status'],'edit_postimage_supported')

    def test_write_existing_file_lower_grade(self):
        self.assertEqual(tool_alignment({'content':'final'},'initial','final',0,5)['status'],'write_snapshot_supported')

    def test_deletions_have_anchors(self):
        self.assertEqual(changed_spans('abc','ac'),[(1,1)])

    def test_rename_numstat(self):
        self.assertEqual(numstats('2\t1\tsrc/{old => new}/app.py')['src/new/app.py'],(2,1))

    def test_dataset_csv_numstat(self):
        self.assertEqual(numstats('insertions,deletions,path\n2,1,"src/a,b.py"\n')['src/a,b.py'],(2,1))

    def test_delete_argument_tool_edit(self):
        before='logger.info("x", extra=x)'
        after='logger.info("x")'
        match=tool_alignment({'old_string':', extra=x','new_string':''},before,after,0,len(after))
        self.assertEqual(match['status'],'exact_edit_supported')

    def test_same_log_but_different_changed_characters(self):
        before='logger.info("stable", old_arg)\n'
        after='logger.info("stable", new_arg)\n'
        p,counts=patch(before,after)
        _,blocks=restore_parent(after,p,counts)
        tools=[{'payload':{'old_string':'"earlier"','new_string':'"stable"'},'reference':{}}]
        result=align_file(before,after,blocks,[log(before,before.strip())],[log(after,after.strip())],tools)
        self.assertEqual(result[0]['attribution_grade'],'file_attribution_only')
        self.assertEqual(result[0]['tool_evidence'][0]['status'],'tool_change_does_not_overlap_commit_log_change')

    def test_structured_patch_coordinates_disambiguate(self):
        before='logger.info("old")\nlogger.info("new")\n'
        after='logger.info("new")\nlogger.info("new")\n'
        tool={'structured_patch':[{'oldStart':1,'oldLines':1,'newStart':1,'newLines':1,'lines':['-logger.info("old")','+logger.info("new")']}]}
        self.assertEqual(tool_alignment(tool,before,after,0,18)['status'],'exact_structured_patch_supported')

    def test_structured_patch_requires_exact_postimage(self):
        tool={'structured_patch':[{'oldStart':1,'oldLines':1,'newStart':1,'newLines':1,'lines':['-logger.info("old")','+logger.info("agent")']}]}
        self.assertEqual(tool_alignment(tool,'logger.info("old")\n','logger.info("human")\n',0,20)['status'],'no_supported_content_alignment')

    def test_unsupported_tool_payload_is_not_silently_positive(self):
        self.assertEqual(tool_alignment({'tool_name':'apply_patch','structured_patch':{'unexpected':'shape'}},'x','y',0,1)['status'],'no_supported_content_alignment')

    def test_guarded_preimage_gate(self):
        self.assertEqual(tool_alignment({'old_string':'old','new_string':'new','_unverified_preimage':True},'old','new',0,3)['status'],'tool_preimage_not_in_guarded_source_versions')

    def test_patch_deletes_entire_log_no_post_candidate(self):
        before='logger.info("removed")\nx=1\n'
        after='x=1\n'
        p,counts=patch(before,after)
        _,blocks=restore_parent(after,p,counts)
        self.assertEqual(align_file(before,after,blocks,[log(before,'logger.info("removed")')],[],[]),[])

    def test_existing_detector_end_to_end_multiline(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
        from agentlog_unified.detector import detect_snapshot
        before='import logging\nlogger=logging.getLogger(__name__)\nlogger.info(\n "value=%s",\n old_value\n)\n'
        after=before.replace('old_value','new_value')
        p,counts=patch(before,after)
        _,blocks=restore_parent(after,p,counts)
        oldlogs=locate_entities(before,detect_snapshot({'app.py':before})['entities'])
        newlogs=locate_entities(after,detect_snapshot({'app.py':after})['entities'])
        tools=[{'payload':{'old_string':'old_value','new_string':'new_value'},'reference':{'tool_index_0based':0}}]
        result=align_file(before,after,blocks,oldlogs,newlogs,tools)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['change_kind'],'modified')
        self.assertEqual(result[0]['attribution_grade'],'exact_tool_change_supported')

    def test_existing_detector_ignores_comment_and_string(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
        from agentlog_unified.detector import detect_snapshot
        source='# logger.info("not executable")\ns = \'logger.info("literal")\'\n'
        self.assertEqual(detect_snapshot({'app.py':source})['entities'],[])

    def test_adjacent_preimage_trailing_newline_not_same_block(self):
        before='foo\nlogger.info("old")\n'
        after='foo\nlogger.info("new")\n'
        p,counts=patch(before,after)
        _,blocks=restore_parent(after,p,counts)
        tools=[{'payload':{'old_string':'foo\n','new_string':'logger.info("new")\n'},'reference':{}}]
        result=align_file(before,after,blocks,[log(before,'logger.info("old")')],[log(after,'logger.info("new")')],tools)
        self.assertEqual(result[0]['attribution_grade'],'tool_postimage_supported')
        self.assertEqual(result[0]['tool_evidence'][0]['downgrade_reason'],'preimage_not_in_same_commit_change_block')


if __name__ == '__main__':
    unittest.main()
