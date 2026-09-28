"""Replay read-only connector receipts without inventing server response headers."""
import hashlib
import json
from pathlib import Path


def install(client, failures_dir=None):
    original = client.get
    failures_dir = Path(failures_dir) if failures_dir else None

    def get(endpoint):
        url = client._url(endpoint)
        key = hashlib.sha256(url.encode()).hexdigest()
        cached = client.cache_dir / (key + '.json')
        failure = failures_dir / (key + '.json') if failures_dir else None
        if not cached.exists() and failure and failure.exists():
            receipt = json.loads(failure.read_text(encoding='utf-8'))
            if receipt.get('url') != url:
                raise ValueError('connector_failure_url_mismatch')
            client.last_headers = {}
            client.last_collected_at = receipt.get('collected_at')
            client.last_source = 'connector_failure_receipt'
            return client._failure(url, receipt.get('error_type', 'connector_read_failed'),
                                   receipt.get('retryable', True), receipt.get('reason', 'Connector read failed'),
                                   failure_receipt=str(failure.resolve()))
        value = original(endpoint)
        if cached.exists() and value is not None:
            envelope = json.loads(cached.read_text(encoding='utf-8'))
            if envelope.get('url') != url:
                raise ValueError('connector_success_url_mismatch')
            adapter = envelope.get('connector_adapter') or {}
            next_url = adapter.get('next_url')
            if next_url:
                if adapter.get('pagination_basis') != 'full_100_row_page_request_next_explicitly':
                    raise ValueError('unverified_connector_pagination_basis')
                from urllib.parse import urlparse, parse_qs
                current, nxt = urlparse(url), urlparse(client._url(next_url))
                page = int(parse_qs(current.query).get('page', ['1'])[0])
                next_page = int(parse_qs(nxt.query).get('page', ['1'])[0])
                if (not isinstance(value, list) or len(value) != 100 or current.path != nxt.path
                        or next_page != page + 1):
                    raise ValueError('invalid_connector_next_page')
                # Runtime adapter instruction, never persisted as a server header.
                client.last_headers = {**client.last_headers, 'link': '<' + next_url + '>; rel="next"'}
        return value

    client.get = get
    return original
