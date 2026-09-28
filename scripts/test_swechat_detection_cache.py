import sys,copy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agentlog_unified import detector
from swechat_exact_detection_cache import install

def test_cached_full_snapshot_output_equals_original_across_edits():
    snapshots=[{'x.go':'package main\nimport "log"\nfunc main() { log.Print("old") }\n',
                'x.js':'const token = "fixture"; console.info(token);'},
               {'x.go':'package main\nimport "log"\nfunc main() { log.Print("new") }\n',
                'x.js':'const token = "fixture"; console.info(token);','other.py':'print("context")\n'}]
    original=[detector.detect_snapshot(s) for s in snapshots]
    finish=install(detector)
    try:
        assert [detector.detect_snapshot(s) for s in snapshots]==original
        first=detector.detect_snapshot(snapshots[0]);first['entities'][0]['statement']='mutated by caller'
        assert detector.detect_snapshot(snapshots[0])==original[0]
    finally:stats=finish()
    assert stats['_go_entities']['hits']>0 and stats['_lexical_entities']['hits']>0
