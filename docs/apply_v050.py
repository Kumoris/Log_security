"""Apply the reviewed, frozen local patches and retain a change receipt."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
receipt = BASE / 'docs/aidev_v050_apply_execution.json'
if receipt.exists():
    raise FileExistsError(receipt)
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
snapshot = lambda: {str(p.relative_to(BASE)): digest(p) for p in sorted([
    *(BASE / 'src/agentlog_unified').glob('*.py'), *(BASE / 'tests').glob('test_*.py')])}
before = snapshot()
assert before == json.loads((BASE / 'docs/aidev_v050_baseline.json').read_text())['source_before']
changes = {}
for location, field in [('/private/tmp/taxonomy_v050_stage', 'files'),
                        ('/private/tmp/structured_parent_v050_stage', 'owned_files')]:
    stage = Path(location)
    manifest = json.loads((stage / 'freeze_manifest.json').read_text())
    for relative, expected in manifest[field].items():
        assert digest(stage / relative) == expected, relative
        changes[relative] = (stage / relative).read_bytes()
storage_stage = Path('/private/tmp/agentlog_v050_storage_stage')
for relative in ['src/agentlog_unified/storage.py', 'tests/test_redaction_identifier_keys.py']:
    changes[relative] = (storage_stage / relative).read_bytes()
for relative, data in changes.items():
    (BASE / relative).write_bytes(data)
replacements = {
    'src/agentlog_unified/__init__.py': ('0.4.9', '0.5.0'),
    'pyproject.toml': ('0.4.9', '0.5.0'),
    'src/agentlog_unified/taxonomy.py': ('1.1.0', '1.2.0'),
    'src/agentlog_unified/content_types.py': ('1.1.0', '1.2.0'),
    'tests/test_content_types.py': ('1.1.0', '1.2.0'),
    'tests/test_content_repair.py': ('1.1.0', '1.2.0'),
    'tests/test_type_audit.py': ('1.1.0', '1.2.0'),
}
for relative, (old, new) in replacements.items():
    path = BASE / relative
    text = path.read_text()
    assert old in text, relative
    path.write_text(text.replace(old, new))
after = snapshot()
receipt.write_text(json.dumps({'applied_at': datetime.now(timezone.utc).isoformat(),
    'source_before': before, 'source_after': after,
    'changed_files': [p for p in after if before.get(p) != after[p]],
    'staged_paths': ['/private/tmp/taxonomy_v050_stage', '/private/tmp/structured_parent_v050_stage',
                     str(storage_stage)], 'package_version': '0.5.0', 'taxonomy_version': '1.2.0',
    'structured_detector_version': '1.1.0', 'catalog_subtypes_unchanged': 49},
    ensure_ascii=False, indent=2) + '\n')
print(json.dumps({'changed_files': [p for p in after if before.get(p) != after[p]],
                  'receipt': str(receipt)}, ensure_ascii=False))
