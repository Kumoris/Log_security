"""Pilot selection must not read sensitivity labels or duplicate a repository."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]/'examples'))
from prepare_reference_pilot import choose, eligible


def test_selection_ignores_sensitive_labels_and_keeps_language_strata():
    rows = [{'repository':'r/'+str(i),'sha':str(i)*40,'side':'after','change_basis':'statement_lines',
             'entity':{'path':'src/app'+extension,'taxonomy_labels':[]}}
            for i,extension in enumerate(('.py','.go','.ts','.py'))]
    baseline = choose(eligible(rows))
    for row in rows:
        row['entity']['taxonomy_labels'] = ['password','private_key']
    assert choose(eligible(list(reversed(rows)))) == baseline
    assert len(baseline) == len({r for r,s in baseline}) == 3
    rows[0]['entity']['path'] = 'tests/app.py'
    rows[1]['side'] = 'before'
    assert (rows[0]['repository'],rows[0]['sha']) not in eligible(rows)
    assert (rows[1]['repository'],rows[1]['sha']) not in eligible(rows)
