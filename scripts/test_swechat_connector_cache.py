import hashlib
import json
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from agentlog_unified.github_client import GitHubClient
from swechat_connector_cache import install


def save(root, url, **kwargs):
    root.mkdir(parents=True, exist_ok=True)
    (root / (hashlib.sha256(url.encode()).hexdigest() + '.json')).write_text(
        json.dumps(dict(url=url, **kwargs)), encoding='utf-8')


def test_connector_pagination_and_actual_failure(tmp_path):
    client = GitHubClient(tmp_path / 'success', offline=True)
    failures = tmp_path / 'failures'
    url = 'https://api.github.com/repos/synthetic/fixture/pulls/1/comments?per_page=100'
    nxt = url + '&page=2'
    save(client.cache_dir, url, data=[{'id': n} for n in range(100)], headers={},
         connector_adapter=dict(next_url=nxt, pagination_basis='full_100_row_page_request_next_explicitly'))
    save(failures, nxt, error_type='connector_HTTP_404', reason='Repository resource inaccessible')
    install(client, failures)
    assert len(client.paginate(url)) == 100
    assert client.failures[-1]['error_type'] == 'connector_HTTP_404'
    assert Path(client.failures[-1]['failure_receipt']).exists()
    assert client.requests == 0


def test_success_wins_over_earlier_failure(tmp_path):
    client = GitHubClient(tmp_path / 'success', offline=True)
    url = 'https://api.github.com/repos/synthetic/fixture/issues/2'
    failures = tmp_path / 'failures'
    save(failures, url, error_type='connector_HTTP_404')
    save(client.cache_dir, url, data={'number': 2})
    install(client, failures)
    assert client.get(url)['number'] == 2
    assert not client.failures


def test_reject_different_resource_pagination(tmp_path):
    client = GitHubClient(tmp_path / 'success', offline=True)
    url = 'https://api.github.com/repos/synthetic/fixture/pulls/1/comments?per_page=100'
    save(client.cache_dir, url, data=[{}] * 100,
         connector_adapter=dict(next_url=url.replace('/1/', '/2/') + '&page=2',
                                pagination_basis='full_100_row_page_request_next_explicitly'))
    install(client)
    with pytest.raises(ValueError, match='invalid_connector_next_page'):
        client.get(url)


def test_comment_locator_index_keeps_endpoint_and_actual_page(tmp_path):
    import agent_log_motivation_v11 as m
    client=GitHubClient(tmp_path/'success',offline=True)
    endpoint='https://api.github.com/repos/synthetic/fixture/pulls/1/comments'
    other='https://api.github.com/repos/synthetic/fixture/pulls/2/comments'
    save(client.cache_dir,endpoint+'?per_page=100',data=[{'id':1}])
    save(client.cache_dir,other+'?per_page=100',data=[{'id':2}])
    collector=m.Collector(client,m.EvidenceStore())
    assert collector.cache_path(endpoint,True,2) is None
    save(client.cache_dir,endpoint+'?per_page=100&page=2',data=[{'id':2}])
    actual=collector.cache_path(endpoint,True,2)
    assert json.loads(Path(actual).read_text())['url']==endpoint+'?per_page=100&page=2'
    assert collector.cache_path(other,True,2)!=actual
