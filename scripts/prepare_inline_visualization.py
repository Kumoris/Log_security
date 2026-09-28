"""Validate a fragment and emit an executor-native inline reference.

Use after a renderer, especially a Windows renderer called from WSL. This
checks the local delivery boundary, not the Codex UI's private read endpoint.
Does not change the HTML or bypass the supplied allowed root.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re


def executor_path(value, platform=None):
    platform = os.name if platform is None else platform
    if not value or '\x00' in value or value.startswith(('file:', 'http:', 'https:')):
        raise ValueError('Expected an absolute filesystem path, not a URL')
    if platform == 'posix':
        match = re.fullmatch(r'([A-Za-z]):[\\/](.*)', value)
        if match:
            value = '/mnt/' + match[1].lower() + '/' + match[2].replace('\\', '/')
        if not value.startswith('/') or value.startswith('//'):
            raise ValueError('Expected an executor-side POSIX absolute path')
    else:
        if not re.match(r'^[A-Za-z]:[\\/]', value):
            raise ValueError('Expected a Windows drive-qualified absolute path')
    return value


def prepare(value, allowed_root):
    path = Path(executor_path(value)).resolve(strict=True)
    root = Path(executor_path(allowed_root)).resolve(strict=True)
    if not path.is_relative_to(root):
        raise ValueError('Fragment is outside the supplied allowed root')
    if not path.is_file() or path.suffix.lower() != '.html':
        raise ValueError('Expected an existing HTML file')
    data = path.read_bytes()
    if not 0 < len(data) < 1_000_000:
        raise ValueError('Fragment must be nonempty and under 1 MB')
    html = data.decode('utf-8')
    if re.search(r'<(?:!doctype|html|head|body)(?:\s|>)', html, re.I):
        raise ValueError('Expected an inline fragment, not a full HTML document')
    if not re.search(r'<[a-z][\w:-]*\b', html, re.I):
        raise ValueError('No markup found')
    payload = {'path': str(path)}
    reference = '\ue200visualize\ue202' + json.dumps(payload, ensure_ascii=False, separators=(',', ':')) + '\ue201'
    return {'requested_path': value, **payload, 'executor_platform': os.name,
            'path_changed': value != str(path), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'reference': reference,
            'local_validation': 'PASS', 'client_read_and_render': 'not_observed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', required=True)
    parser.add_argument('--allowed-root', required=True)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    result = prepare(args.path, args.allowed_root)
    encoded = json.dumps(result, ensure_ascii=False, indent=2)
    if args.receipt:
        with args.receipt.open('x', encoding='utf-8') as out:
            out.write(encoded + '\n')
    print(encoded)

if __name__ == '__main__':
    main()
