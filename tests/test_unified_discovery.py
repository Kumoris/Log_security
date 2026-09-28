from agentlog_unified.discovery import discover_prs
from agentlog_unified.ingest import ingest_records


def test_search_partitions_deduplicates_and_does_not_assign_authorship():
    class Client:
        requests = 0
        def get(self, url):
            self.requests += 1
            return {'total_count': 1100 if self.requests == 1 else 1, 'items': [
                {'html_url': 'https://github.com/example/project/pull/7'}]}
    c = Client()
    result = discover_prs(c, ['repo:example/project author:copilot'], '2025-01-01', '2025-01-02')
    assert len(result['prs']) == 1 and c.requests == 3
    assert [p['status'] for p in result['partitions']] == ['split', 'complete', 'complete']
    assert result['prs'][0]['pr_actor_type'] == 'unknown'
    assert all(not e['verified'] for e in result['prs'][0]['provenance_evidence'])


def test_discovery_budget_and_txt_input(tmp_path):
    class Client:
        requests = 0
        def get(self, url):
            self.requests += 1
            return {'total_count': 1100, 'items': []}
    result = discover_prs(Client(), ['repo:example/project'], '2025-01-01', '2025-01-02', 1)
    assert not result['complete'] and result['partitions'][-1]['status'] == 'budget_exceeded'
    p = tmp_path/'prs.txt'
    p.write_text('# inputs\nhttps://github.com/example/project/pull/7\ninvalid\n')
    imported = ingest_records(p)
    assert len(imported['prs']) == 1 and len(imported['gaps']) == 1


def test_duplicate_pages_are_partial_not_complete():
    class Client:
        requests=0
        def get(self,url):
            self.requests+=1
            return {'total_count':200,'items':[{'html_url':'https://github.com/a/b/pull/1'}]*100}
    result=discover_prs(Client(),['repo:a/b'],'2025-01-01','2025-01-01')
    assert not result['complete'] and result['partitions'][0]['unique_prs']==1
