"""Public query workflow with synthetic sources; never contacts a real service."""
import copy
import contextlib
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import es
from test_setup_mcp import server, TOOLS, search_response


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('INVENTORY_TEST_TMP'))
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.output = self.repo / '.local/elasticsearch-query/agent/source'
        self.output.mkdir(parents=True)
        self.config = self.repo / 'authorized.env'
        self.config.write_text('ES_URL=https://es.example.test\nES_API_KEY=synthetic-secret-key\nES_INDEX_PATTERNS=logs-*\n')
        self.profile = es.validate({'mode': 'es-api', 'connection_ref': 'example',
            'repo_root': str(self.repo), 'agent_id': 'agent', 'output_dir': '.',
            'env_file': str(self.config), 'index_patterns': ['logs-*']}, self.output)
        self.scope = {'repo_root': str(self.repo.resolve()), 'agent_id': 'agent'}
        self.source = {'transport': 'direct-es-api', 'es_url': 'https://es.example.test', 'index_patterns': ['logs-*']}
        self.save_inventory()
        self.request = {'index': 'logs-a', 'start': '2026-11-01T00:00:00Z',
            'end': '2026-11-02T00:00:00Z', 'fields': ['@timestamp', 'deviceAction'],
            'filters': {'deviceAction': 'deny'}, 'limit': 1}
        self.calls = []
        self.response = {'timed_out': False, '_shards': {'failed': 0},
            'hits': {'total': {'value': 1, 'relation': 'eq'}, 'hits': [{'_source': {
                '@timestamp': '2026-11-01T01:00:00Z', 'deviceAction': 'deny',
                'unrequested': 'MUST-NOT-PERSIST'}}]}}

    def save_inventory(self):
        (self.output / 'setup.json').write_text(json.dumps({'schema_version': 3, 'scope': self.scope, 'source': self.source, 'inventory_report_stem': 'inventory'}))
        (self.output / 'inventory.json').write_text(json.dumps({'scope': self.scope, 'source': self.source, 'indices': [], 'devices': []}))

    def client(self):
        owner = self
        class Client:
            url = urlsplit('https://es.example.test')
            def request(self, method, path, body=None):
                owner.calls.append((method, path, body))
                if path.startswith('/_resolve/index/'):
                    return {'indices': [{'name': 'logs-a'}]}
                if '_field_caps' in path:
                    return {'fields': {'@timestamp': {'date': {'searchable': True, 'aggregatable': True}},
                        'deviceAction': {'keyword': {'searchable': True, 'aggregatable': True}}}}
                return owner.response
        return Client()

    def run_direct(self, request=None):
        with patch.object(es.direct, 'ES', return_value=self.client()):
            return es.run_query(self.profile, self.request if request is None else request)

    def test_direct_query_constrains_time_fields_and_saves_projected_evidence(self):
        value = {**self.request, 'query': {'bool': {'should': [
            {'term': {'deviceAction': 'deny'}}, {'term': {'deviceAction': 'drop'}}], 'minimum_should_match': 1}}}
        result = self.run_direct(value)
        body = self.calls[-1][2]
        self.assertEqual(body['_source'], self.request['fields'])
        self.assertEqual(body['size'], 1)
        self.assertEqual(body['query']['bool']['filter'][0]['range']['@timestamp']['lt'], '2026-11-02T00:00:00+00:00')
        self.assertEqual(body['query']['bool']['must'], [value['query']])
        self.assertEqual(result['result']['total'], {'value': 1, 'relation': 'eq'})
        evidence = Path(result['evidence_file'])
        self.assertTrue(evidence.is_file())
        text = evidence.read_text()
        self.assertNotIn('MUST-NOT-PERSIST', text)
        self.assertNotIn('synthetic-secret-key', text)
        self.assertEqual(json.loads(text)['scope'], self.scope)

    def test_scripts_unbounded_source_and_outside_index_fail_before_client_creation(self):
        invalid = [
            {**self.request, 'query': {'script': {'script': 'danger'}}},
            {**self.request, 'index': 'other-a'},
            {**self.request, 'index': '_all'},
            {**self.request, 'fields': ['*']},
            {**self.request, 'limit': 101},
            {**self.request, 'end': '2026-11-03T00:00:00Z'},
            {**self.request, 'start': None},
            {**self.request, 'size': 100000},
        ]
        for value in invalid:
            with self.subTest(value=value), patch.object(es.direct, 'ES') as client:
                with self.assertRaises(ValueError):
                    es.run_query(self.profile, value)
                client.assert_not_called()

    def test_source_and_agent_mismatch_stop_before_network(self):
        self.source['es_url'] = 'https://other.example.test'
        self.save_inventory()
        with self.assertRaises(ValueError):
            self.run_direct()
        self.assertEqual(self.calls, [])
        self.scope['agent_id'] = 'another-agent'
        self.save_inventory()
        with patch.object(es.direct, 'ES') as client:
            with self.assertRaises(ValueError):
                es.run_query(self.profile, self.request)
            client.assert_not_called()

    def test_query_current_source_must_match_bound_setup_and_report(self):
        self.config.write_text('ES_URL=https://other.example.test\nES_API_KEY=synthetic\nES_INDEX_PATTERNS=logs-*\n')
        client = self.client()
        client.url = urlsplit('https://other.example.test')
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        with patch.object(es.direct, 'ES', return_value=client):
            with self.assertRaises(ValueError):
                es.run_query(self.profile, self.request)
        self.assertEqual(self.calls, [])
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir() if p.name != '.write.lock'}, before)

    def test_mcp_adapter_preserves_supported_constraints_and_refuses_unsupported_ones(self):
        request = es.query_request(self.request)
        schema = copy.deepcopy(TOOLS[2]['inputSchema'])
        with self.assertRaises(es.mcp.MCPError):
            es.mcp.search_arguments(request, schema)
        for extra in ({'time_field': 'deviceReceiptTime', 'filters': {}},
                {'aggregate_field': 'deviceAction', 'filters': {}}, {'query': {'match_all': {}}, 'filters': {}}):
            unsupported = copy.deepcopy(schema)
            unsupported['properties'].pop('aggregate_field', None)
            with self.assertRaises(es.mcp.MCPError):
                es.mcp.search_arguments({**request, **extra}, unsupported)
        schema['properties'].update(filters={}, time_field={})
        arguments = es.mcp.search_arguments(request, schema)
        self.assertEqual(arguments['filters'], {'deviceAction': 'deny'})
        self.assertEqual(arguments['time_field'], '@timestamp')
        schema['required'].append('nonce')
        schema['properties']['nonce'] = {}
        with self.assertRaises(es.mcp.MCPError):
            es.mcp.search_arguments(request, schema)

    def test_failures_are_not_zero_and_gte_remains_partial(self):
        for invalid in ({**self.response, 'timed_out': True},
                {k: v for k, v in self.response.items() if k != '_shards'}):
            self.response = invalid
            with self.assertRaises(ValueError):
                self.run_direct()
            self.assertFalse((self.output / 'queries').exists())
        self.response = {'timed_out': False, '_shards': {'failed': 0},
            'hits': {'total': {'value': 10000, 'relation': 'gte'}, 'hits': []}}
        self.assertEqual(self.run_direct()['result']['status'], 'partial')

    def test_cli_direct_query_uses_profile_and_request_files(self):
        profile = self.output / 'profile.json'
        profile.write_text(json.dumps(self.profile))
        request = self.output / 'request.json'
        request.write_text(json.dumps(self.request))
        output = io.StringIO()
        with patch.object(es.direct, 'ES', return_value=self.client()), \
                patch.object(sys, 'argv', ['es.py', 'query', '--profile', str(profile), '--request', str(request)]), \
                contextlib.redirect_stdout(output):
            self.assertEqual(es.main(), 0)
        self.assertEqual(json.loads(output.getvalue())['result']['total']['value'], 1)

    def test_top_values_preserve_truncation_instead_of_claiming_full_inventory(self):
        self.response['aggregations'] = {'top_values': {'buckets': [
            {'key': 'deny', 'doc_count': 5, 'unrequested': 'MUST-NOT-PERSIST'}],
            'sum_other_doc_count': 10, 'doc_count_error_upper_bound': 0}}
        result = self.run_direct({**self.request, 'aggregate_field': 'deviceAction'})
        self.assertEqual(result['result']['status'], 'partial')
        self.assertEqual(result['result']['top_values']['sum_other_doc_count'], 10)
        self.assertNotIn('unrequested', result['result']['top_values']['buckets'][0])

    def test_native_mcp_does_not_open_es_client_or_read_es_credentials(self):
        profile = {**self.profile, 'mode': 'mcp-native'}
        with patch.object(es.direct, 'ES') as client, patch.object(es.direct, 'load_env') as config:
            with self.assertRaisesRegex(ValueError, '原生 MCP'):
                es.run_query(profile, self.request)
            client.assert_not_called()
            config.assert_not_called()

    def test_same_source_concurrent_writes_stop_before_network_and_lock_releases(self):
        with es.output_lock(self.profile):
            with patch.object(es.direct, 'ES') as client:
                with self.assertRaisesRegex(ValueError, '操作執行中'):
                    es.run_query(self.profile, self.request)
                client.assert_not_called()
            other = {**self.profile, 'agent_id': 'other-agent', 'output_dir': str(self.repo / 'other-agent')}
            with es.output_lock(other):
                pass
        with self.assertRaises(RuntimeError):
            with es.output_lock(self.profile):
                raise RuntimeError('synthetic failure')
        with es.output_lock(self.profile):
            pass

    def test_locally_truncated_top_values_are_marked_partial(self):
        self.response['aggregations'] = {'top_values': {
            'buckets': [{'key': str(i), 'doc_count': 1} for i in range(21)],
            'sum_other_doc_count': 0, 'doc_count_error_upper_bound': 0}}
        result = self.run_direct({**self.request, 'aggregate_field': 'deviceAction'})
        self.assertEqual(result['result']['status'], 'partial')
        self.assertEqual(len(result['result']['top_values']['buckets']), 20)

    def test_http_mcp_cli_setup_query_and_inventory_use_one_profile_without_es_key(self):
        runtime = self.repo / 'runtime-skill'
        runtime.mkdir()
        for name in ('scripts', 'references'):
            shutil.copytree(SCRIPTS.parent / name, runtime / name,
                ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copy2(SCRIPTS.parent / 'SKILL.md', runtime / 'SKILL.md')
        self.assertFalse((runtime / 'tests').exists())
        with server(expected_token=None) as (host, url):
            profile = self.output / 'profile.json'
            # New source uses a separate Agent data directory.
            directory = self.repo / 'mcp-agent'
            directory.mkdir()
            profile = directory / 'profile.json'
            profile.write_text(json.dumps({'mode': 'mcp-http', 'repo_root': str(self.repo),
                'agent_id': 'mcp-agent', 'connection_ref': 'fixture-mcp', 'output_dir': '.',
                'url': url, 'auth': 'none', 'index_patterns': ['logs-*']}))
            request = directory / 'request.json'
            request.write_text(json.dumps({k: v for k, v in self.request.items() if k != 'filters'}))
            environment = {k: v for k, v in os.environ.items() if not k.startswith(('ES_', 'MCP_', 'ELASTICSEARCH_'))}
            commands = [('setup', '--profile', str(profile)),
                ('query', '--profile', str(profile), '--request', str(request)),
                ('inventory', '--input-dir', str(directory), '--repo-root', str(self.repo), '--agent-id', 'mcp-agent')]
            for command in commands:
                result = subprocess.run([sys.executable, '-B', str(runtime / 'scripts/es.py'), *command],
                    env=environment, cwd=self.repo, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            evidence = set((directory / 'queries').glob('*.json'))
            self.assertTrue(evidence)
            for value in ({**self.request}, {**self.request, 'filters': {}, 'time_field': 'deviceReceiptTime'},
                    {**self.request, 'filters': {}, 'query': {'match_all': {}}}):
                request.write_text(json.dumps(value))
                before = len(host.search_args)
                result = subprocess.run([sys.executable, '-B', str(runtime / 'scripts/es.py'),
                    'query', '--profile', str(profile), '--request', str(request)],
                    env=environment, cwd=self.repo, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(len(host.search_args), before)
                self.assertEqual(set((directory / 'queries').glob('*.json')), evidence)


if __name__ == '__main__':
    unittest.main()
