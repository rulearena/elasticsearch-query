"""End-to-end MCP-only setup with a local protocol fixture; no ES credentials."""
import copy
import contextlib
import http.server
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import inventory_es as direct
import mcp_inventory as mcp
import es as setup

TEST_ROOT = os.environ.get('INVENTORY_TEST_TMP')
TOKEN = 'synthetic-mcp-secret-never-publish'
TOOLS = [
    {'name': 'list_indices', 'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'get_mapping', 'inputSchema': {'type': 'object', 'properties': {'index': {'type': 'string'}}}},
    {'name': 'search_events', 'inputSchema': {'type': 'object', 'required': ['index', 'start', 'end'],
        'properties': {name: {} for name in ('index', 'start', 'end', 'fields', 'limit', 'aggregate_field')},
        'additionalProperties': False}}]
FIELDS = {name: {kind: {'searchable': True, 'aggregatable': True}} for name, kind in
    (('deviceAddress', 'ip'), ('deviceVendor', 'keyword'), ('deviceProduct', 'keyword'),
     ('@timestamp', 'date'), ('deviceAction', 'keyword'), ('sourceAddress', 'ip'))}


def search_response():
    return {'timed_out': False, 'shards': {'failed': 0},
        'hits': {'total': {'value': 10000, 'relation': 'gte'}, 'hits': [{'_source': {
            'deviceAddress': '192.0.2.1', 'deviceVendor': 'Vendor A', 'deviceProduct': 'Firewall',
            'deviceAction': 'deny', 'sourceAddress': '198.51.100.99', 'message': 'RAW-SHOULD-NOT-PERSIST'}}]},
        'aggregations': {'top_values': {'buckets': [{'key': '192.0.2.1', 'doc_count': 5},
            {'key': '192.0.2.2', 'doc_count': 3}], 'sum_other_doc_count': 9, 'doc_count_error_upper_bound': 0}}}


def capture():
    return {'connection_ref': 'fixture-mcp', 'tools': TOOLS, 'indices_result': ['logs-a', 'logs-b'],
        'records': [{'index': 'logs-a', 'start': '2026-11-01T00:00:00+00:00',
            'end': '2026-11-02T00:00:00+00:00', 'aggregate_field': 'deviceAddress',
            'mapping_result': {'fields': FIELDS}, 'search_result': search_response()}]}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        server = self.server
        server.calls.append(self.path)
        expected_token = self.server.expected_token
        if expected_token is not None and self.headers.get('Authorization') != 'Bearer ' + expected_token:
            self.send_response(401)
            self.end_headers()
            return
        value = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method = value['method']
        if method != 'initialize' and self.headers.get('Mcp-Session-Id') != 'fixture-session':
            self.send_response(400)
            self.end_headers()
            return
        if method == 'notifications/initialized':
            self.send_response(202)
            self.end_headers()
            return
        if server.redirect:
            self.send_response(302)
            self.send_header('Location', 'http://127.0.0.1:1/should-never-be-contacted')
            self.end_headers()
            return
        params = value.get('params', {})
        if method == 'initialize':
            result = {'protocolVersion': '2025-03-26', 'capabilities': {'tools': {}}}
        elif method == 'tools/list':
            result = {'tools': TOOLS[2:]} if params.get('cursor') else {'tools': TOOLS[:2], 'nextCursor': 'page-2'}
        elif method == 'tools/call':
            server.tools_called.append(params['name'])
            if params['name'] == 'list_indices':
                result = {'structuredContent': {'result': ['logs-a', 'logs-b']}}
            elif params['name'] == 'get_mapping':
                result = {'structuredContent': {'fields': FIELDS}}
            elif params['name'] == 'search_events':
                server.search_args.append(params['arguments'])
                schema = TOOLS[2]['inputSchema']
                if set(params['arguments']) - schema['properties'].keys():
                    self.send_response(400)
                    self.end_headers()
                    return
                response = search_response()
                if server.fail_search:
                    response['timed_out'] = True
                result = {'structuredContent': response}
            else:
                self.send_response(400)
                self.end_headers()
                return
        else:
            self.send_response(400)
            self.end_headers()
            return
        raw = json.dumps({'jsonrpc': '2.0', 'id': value['id'], 'result': result}).encode()
        self.send_response(200)
        self.send_header('Mcp-Session-Id', 'fixture-session')
        if server.sse:
            raw = b'data: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n' + b'data: ' + raw + b'\n\n'
            self.send_header('Content-Type', 'text/event-stream')
        else:
            self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@contextlib.contextmanager
def server(sse=False, fail_search=False, redirect=False, expected_token=TOKEN):
    instance = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    instance.sse, instance.fail_search, instance.redirect = sse, fail_search, redirect
    instance.expected_token = expected_token
    instance.calls, instance.tools_called, instance.search_args = [], [], []
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance, 'http://127.0.0.1:' + str(instance.server_port) + '/mcp'
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


class SetupTests(unittest.TestCase):
    def profile(self, value, base):
        return setup.validate({'repo_root': str(base), 'agent_id': 'test-agent', **value}, base)

    def test_documented_profiles_save_beside_profile_without_nested_output_paths(self):
        references = SCRIPTS.parent / 'references'
        examples = []
        for name in ('connection.md',):
            for block in re.findall(r'```json\s*\n(.*?)\n```',
                    (references / name).read_text(), re.DOTALL):
                value = json.loads(block)
                if 'mode' in value:
                    examples.append(value)
        self.assertEqual({v['mode'] for v in examples}, set(setup.MODES))
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            repo = Path(folder)
            for example in examples:
                output = repo / '.local' / 'elasticsearch-query' / 'agent-example' / example['mode']
                output.mkdir(parents=True)
                value = {**example, 'repo_root': str(repo)}
                if value['mode'] == 'mcp-http':
                    value['url'] = 'https://mcp.example.test/mcp'
                if value['mode'] == 'es-api':
                    value['env_file'] = str(repo / 'authorized.env')
                profile_file = output / 'profile.json'
                profile_file.write_text(json.dumps(value))
                profile = setup.validate(json.loads(profile_file.read_text()), profile_file.parent)
                self.assertEqual(Path(profile['output_dir']), output.resolve())

    def test_native_setup_without_credentials_writes_real_reports_and_state(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            profile = self.profile({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                'output_dir': 'agent-a'}, Path(folder))
            with patch.dict(os.environ, {}, clear=True), \
                    patch.object(direct, 'ES', side_effect=AssertionError('No direct ES allowed')), \
                    patch.object(direct, 'load_env', side_effect=AssertionError('No credentials requested')):
                status = setup.execute(profile, capture())
            self.assertEqual(status['setup_status'], 'ready_with_limits')
            self.assertTrue(status['query_ready'])
            self.assertEqual(status['periodic_refresh'], 'unknown')
            out = Path(profile['output_dir'])
            report = json.loads((out / 'inventory.json').read_text())
            self.assertEqual(report['not_scanned_indices'], ['logs-b'])
            self.assertEqual({d['deviceAddress'] for d in report['devices']}, {'192.0.2.1', '192.0.2.2'})
            self.assertNotIn('198.51.100.99', json.dumps(report['devices']))
            self.assertIsNone(report['indices'][0]['document_count'])
            self.assertIsNone(report['indices'][0]['missing_deviceAddress_documents'])
            for name in ('setup.json', 'inventory.md', 'inventory.json'):
                content = (out / name).read_text()
                self.assertNotIn('RAW-SHOULD-NOT-PERSIST', content)
                self.assertNotIn(TOKEN, content)
            self.assertTrue((out / 'setup.json').is_file())

    def test_http_cli_local_mcp_without_token_completes_inventory_for_two_agents(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder, server(expected_token=None) as (host, url):
            first = None
            for name in ('agent-a', 'agent-b'):
                out = Path(folder) / name
                profile = Path(folder) / (name + '.json')
                profile.write_text(json.dumps({'mode': 'mcp-http', 'connection_ref': 'fixture-mcp',
                    'url': url, 'output_dir': str(out), 'index_patterns': ['logs-*'],
                    'repo_root': folder, 'agent_id': name, 'auth': 'none'}))
                environment = {k: v for k, v in os.environ.items() if not k.startswith('ES_')}
                run = subprocess.run([sys.executable, '-B', str(SCRIPTS / 'es.py'), 'setup',
                    '--profile', str(profile)], env=environment, capture_output=True, text=True, timeout=20)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn('ready_with_limits', run.stdout)
                state = json.loads((out / 'setup.json').read_text())
                self.assertEqual(state['profile']['mode'], 'mcp-http')
                report = json.loads((out / 'inventory.json').read_text())
                self.assertEqual(len(report['indices']), 2)
                self.assertTrue(report['query_ready'])
                self.assertEqual(report['status'], 'partial')
                self.assertEqual(report['indices'][0]['field_value_evidence']['deviceAction'], 'observed_in_sample')
                self.assertNotIn(TOKEN, (out / 'setup.json').read_text())
                if first is None:
                    first = (out / 'inventory.json').read_bytes()
            self.assertEqual((Path(folder) / 'agent-a' / 'inventory.json').read_bytes(), first)
            self.assertEqual(set(host.calls), {'/mcp'})
            self.assertEqual(set(host.tools_called), set(mcp.LOGICAL_TOOLS))
            self.assertTrue(all(a['fields'] and a['limit'] == 3 for a in host.search_args))
            self.assertTrue(all(a['aggregate_field'] == 'deviceAddress' for a in host.search_args))

    def test_streamable_http_sse_session_and_tool_list_pagination(self):
        with server(sse=True, expected_token=None) as (host, url):
            client = mcp.HTTPMCP(url)
            tools = client.initialize()
            self.assertEqual(len(tools), 3)
            client.allowed = {t['name'] for t in tools}
            self.assertEqual(client.call('list_indices', {}), ['logs-a', 'logs-b'])

    def test_failed_queries_do_not_mark_setup_ready_or_report_zero(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            value = capture()
            value['records'][0]['search_result']['timed_out'] = True
            profile = self.profile({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                'output_dir': 'agent'}, Path(folder))
            status = setup.execute(profile, value)
            self.assertFalse(status['query_ready'])
            self.assertEqual(status['setup_status'], 'needs_attention')
            report = json.loads((Path(folder) / 'agent' / 'inventory.json').read_text())
            self.assertTrue(report['errors'])
            self.assertEqual(report['devices'], [])
            self.assertEqual(report['indices'][0]['field_count'], len(FIELDS))

    def test_missing_config_and_native_capture_do_not_ask_for_es_key(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            with self.assertRaisesRegex(direct.ConfigError, 'mode.*connection_ref.*output_dir'):
                self.profile({}, Path(folder))
            profile = self.profile({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                'output_dir': 'agent'}, Path(folder))
            with self.assertRaisesRegex(direct.ConfigError, '不需 ES Key'):
                setup.execute(profile)
            self.assertFalse((Path(folder) / 'agent').exists())

    def test_profile_rejects_secrets_and_es_key_as_mcp_auth(self):
        base = {'mode': 'mcp-native', 'connection_ref': 'fixture-mcp', 'output_dir': 'agent'}
        for extra in ({'api_key': 'secret'}, {'MCP_TOKEN': TOKEN}, {'token_env': 'ES_API_KEY'},
                {'url': 'https://user:secret@example.test/mcp'}, {'url': 'https://example.test/mcp?token=secret'}):
            with self.assertRaises(direct.ConfigError):
                self.profile({**base, **extra}, Path.cwd())

    def test_http_auth_failure_is_actionable_and_no_redirect_is_followed(self):
        with server() as (_, url):
            with self.assertRaisesRegex(mcp.MCPError, '401.*MCP') as error:
                mcp.HTTPMCP(url).initialize()
            self.assertNotIn(TOKEN, str(error.exception))
        with server(redirect=True, expected_token=None) as (_, url):
            with self.assertRaisesRegex(mcp.MCPError, '302'):
                mcp.HTTPMCP(url).initialize()

    def test_native_capture_cannot_mix_sources(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            profile = self.profile({'mode': 'mcp-native', 'connection_ref': 'other-mcp',
                'output_dir': 'agent'}, Path(folder))
            with self.assertRaises(direct.ConfigError):
                setup.execute(profile, capture())

    def test_only_sample_without_aggregation_still_yields_partial_inventory(self):
        row = capture()['records'][0]
        record = mcp.record_from(row['index'], row['mapping_result'], row['search_result'], row['start'], row['end'])
        self.assertEqual(len(record['identity_observations']), 1)
        self.assertEqual(record['status'], 'partial')
        self.assertIsNone(record['missing_deviceAddress_documents'])

    def test_unknown_search_metadata_is_not_validated_query(self):
        row = capture()['records'][0]
        del row['search_result']['hits']['total']
        with self.assertRaises(mcp.MCPError):
            mcp.record_from(row['index'], row['mapping_result'], row['search_result'], row['start'], row['end'])

    def test_index_date_window_requires_confirmed_convention(self):
        fallback = ('2026-11-01T00:00:00+00:00', '2026-11-02T00:00:00+00:00')
        self.assertEqual(mcp.index_window({}, 'logs-20261020', fallback), fallback)
        result = mcp.index_window({'index_date_timezone': 'UTC'}, 'logs-20261020', fallback)
        self.assertEqual(result, ('2026-10-20T00:00:00+00:00', '2026-10-21T00:00:00+00:00'))
        self.assertEqual(mcp.index_window({'index_date_timezone': 'UTC', 'start': fallback[0]},
            'logs-20261020', fallback), fallback)

    def test_mapping_failure_stays_partial_without_name_error_or_false_readiness(self):
        client = Mock()
        client.requests = 4
        client.initialize.return_value = TOOLS
        def call(name, arguments):
            if name == 'list_indices':
                return ['logs-a']
            raise mcp.MCPError('mcp_tool_failed')
        client.call.side_effect = call
        with patch('builtins.print'):
            report = mcp.scan_client(client, {'connection_ref': 'fixture-mcp', 'index_patterns': ['*']})
        self.assertEqual(report['status'], 'partial')
        self.assertFalse(report['query_ready'])
        self.assertEqual(report['errors'][0]['index'], 'logs-a')

    def test_direct_mode_respects_explicit_scope_and_request_budgets(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            config = root / 'direct.env'
            config.write_text('ES_INDEX_PATTERNS=logs-*\n')
            profile = self.profile({'mode': 'es-api', 'connection_ref': 'direct',
                'env_file': str(config), 'output_dir': 'agent', 'index_patterns': ['logs-*'],
                'max_indices': 1, 'max_requests': 5}, root)
            from test_inventory_es import ScanES
            config.write_text('ES_URL=https://es.example.test\nES_API_KEY=synthetic\nES_INDEX_PATTERNS=logs-*\n')
            class BudgetES(ScanES):
                def request(self, method, path, body=None):
                    if path.startswith('/_resolve/index/'):
                        self.requests += 1
                        return {'indices': [{'name': 'logs-a'}, {'name': 'logs-b'}]}
                    return super().request(method, path, body)
            with patch.object(direct, 'ES', BudgetES), patch('builtins.print'):
                state = setup.execute(profile)
            self.assertEqual(state['setup_status'], 'ready_with_limits')
            report = json.loads((root / 'agent/inventory.json').read_text())
            self.assertEqual(report['not_scanned_indices'], ['logs-b'])
            self.assertEqual(report['http_requests'], 3)

    def test_direct_mode_scope_mismatch_stops_before_network(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            config = root / 'direct.env'
            config.write_text('ES_INDEX_PATTERNS=logs-*\n')
            profile = self.profile({'mode': 'es-api', 'connection_ref': 'direct',
                'env_file': str(config), 'output_dir': 'agent', 'index_patterns': ['other-*']}, root)
            with patch.object(direct, 'scan') as run:
                with self.assertRaises(direct.ConfigError):
                    setup.execute(profile)
                run.assert_not_called()

    def test_repo_and_agent_scope_is_required(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            with self.assertRaisesRegex(direct.ConfigError, 'repo_root.*agent_id'):
                setup.validate({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                    'output_dir': 'agent'}, Path(folder))

    def test_output_cannot_escape_repo_or_use_sibling_repo_through_symlink(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            repo_a, repo_b = root / 'repo-a', root / 'repo-b'
            repo_a.mkdir()
            repo_b.mkdir()
            (repo_a / 'escape').symlink_to(repo_b, target_is_directory=True)
            for output in (str(repo_b / 'agent'), str(root / 'global-agent'), str(repo_a / 'escape' / 'agent')):
                with self.assertRaises(direct.ConfigError):
                    setup.validate({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                        'repo_root': str(repo_a), 'agent_id': 'agent-example', 'output_dir': output}, repo_a)

    def test_same_agent_in_two_repos_saves_separate_bound_reports(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            for name in ('repo-a', 'repo-b'):
                repo = root / name
                repo.mkdir()
                profile = setup.validate({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                    'repo_root': str(repo), 'agent_id': 'agent-example',
                    'output_dir': '.local/elasticsearch-query/agent-example/source-a'}, repo)
                status = setup.execute(profile, capture())
                # setup.execute 內部用 Path.resolve()，macOS 的 /var 會解成 /private/var，
                # 期望值要走同一個解析，否則只是符號連結差異就會誤判失敗。
                self.assertEqual(status['scope'], {'repo_root': str(repo.resolve()), 'agent_id': 'agent-example'})
                report = json.loads((Path(profile['output_dir']) / 'inventory.json').read_text())
                self.assertEqual(report['scope'], status['scope'])
            self.assertTrue((root / 'repo-a/.local/elasticsearch-query/agent-example/source-a/setup.json').is_file())
            self.assertTrue((root / 'repo-b/.local/elasticsearch-query/agent-example/source-a/setup.json').is_file())

    def test_copied_other_repo_or_agent_report_is_rejected_before_mcp_calls(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            repo = Path(folder)
            output = repo / 'agent'
            output.mkdir()
            base = {'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                'repo_root': str(repo), 'agent_id': 'agent-example', 'output_dir': str(output)}
            for scope in (None, {'repo_root': str(repo / 'other'), 'agent_id': 'agent-example'},
                    {'repo_root': str(repo), 'agent_id': 'codex'}):
                previous = output / 'inventory.json'
                previous.write_text(json.dumps({'scope': scope}))
                before = previous.read_bytes()
                with patch.object(mcp, 'http_client') as client:
                    with self.assertRaises(direct.ConfigError):
                        setup.validate(base, repo)
                    client.assert_not_called()
                self.assertEqual(previous.read_bytes(), before)

    def test_es_mcp_token_name_is_valid_and_does_not_mean_es_api_key(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            profile = self.profile({'mode': 'mcp-http', 'connection_ref': 'fixture-mcp',
                'url': 'https://mcp.example.test/mcp', 'output_dir': 'agent', 'token_env': 'ES_MCP_TOKEN'}, Path(folder))
            with patch.dict(os.environ, {'ES_MCP_TOKEN': TOKEN}, clear=True):
                client = mcp.http_client(profile)
            self.assertEqual(client.headers['Authorization'], 'Bearer ' + TOKEN)

    def test_env_file_token_placeholder_resolves_only_explicit_reference(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            path = Path(folder) / 'mcp.env'
            path.write_text('MCP_TOKEN="Bearer ${ES_MCP_TOKEN}"\n')
            with patch.dict(os.environ, {'ES_MCP_TOKEN': TOKEN, 'MCP_TOKEN': 'stale-secret',
                    'ES_API_KEY': 'must-not-use'}, clear=True):
                client = mcp.http_client({'url': 'https://mcp.example.test/mcp', 'env_file': str(path)})
            self.assertEqual(client.headers['Authorization'], 'Bearer ' + TOKEN)

    def test_unresolved_or_shell_token_never_reaches_network_or_echoes_value(self):
        for value in ('${UNSET_MCP_TOKEN}', '${ES_API_KEY}', '$(touch MUST-NOT-EXECUTE)',
                'prefix-${UNSET_MCP_TOKEN}', '`echo secret`'):
            with patch.dict(os.environ, {'MCP_TOKEN': value, 'ES_API_KEY': 'es-secret'}, clear=True), \
                    patch.object(mcp, 'HTTPMCP') as client:
                with self.assertRaises(direct.ConfigError) as error:
                    mcp.http_client({'url': 'https://mcp.example.test/mcp'})
                client.assert_not_called()
                self.assertNotIn(value, str(error.exception))
                self.assertNotIn('es-secret', str(error.exception))
        with patch.object(mcp.urllib.request, 'build_opener') as opener:
            with self.assertRaises(direct.ConfigError):
                mcp.HTTPMCP('https://mcp.example.test/mcp', '${UNSET_MCP_TOKEN}')
            opener.assert_not_called()

    def test_token_reference_cycle_is_rejected_and_auth_none_sends_no_token(self):
        with self.assertRaises(direct.ConfigError):
            mcp.resolve_token('${A}', {'A': '${B}', 'B': '${A}'}, {})
        with patch.dict(os.environ, {'MCP_TOKEN': TOKEN}, clear=True):
            client = mcp.http_client({'url': 'http://127.0.0.1:1/mcp', 'auth': 'none'})
        self.assertNotIn('Authorization', client.headers)

    def test_global_profile_file_is_rejected_even_when_output_points_into_repo(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            repo = root / 'repo'
            repo.mkdir()
            profile = root / 'global-profile.json'
            profile.write_text(json.dumps({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                'repo_root': str(repo), 'agent_id': 'agent-example', 'output_dir': str(repo / 'agent')}))
            result = subprocess.run([sys.executable, '-B', str(SCRIPTS / 'es.py'), 'setup',
                '--profile', str(profile)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('profile 也必須保存於目前 repo', result.stdout)
            self.assertFalse((repo / 'agent').exists())


    def test_failed_refresh_preserves_reports_and_last_success_in_every_offline_view(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            profile = self.profile({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                'output_dir': 'agent'}, root)
            success = setup.execute(profile, capture())
            output = Path(profile['output_dir'])
            before = {p.name: p.read_bytes() for p in output.glob('inventory*')}
            with patch.object(mcp, 'from_capture', side_effect=direct.http.client.HTTPException('synthetic-secret')):
                with self.assertRaises(direct.http.client.HTTPException):
                    setup.execute(profile, capture())
            failed = json.loads((output / 'setup.json').read_text())
            self.assertFalse(failed['query_ready'])
            self.assertEqual(failed['last_attempt']['status'], 'failed')
            self.assertEqual(failed['last_success'], success['last_success'])
            self.assertEqual(failed['profile'], success['profile'])
            self.assertNotIn('synthetic-secret', json.dumps(failed))
            self.assertNotIn('stem', json.dumps(failed['last_success']))
            self.assertEqual({p.name: p.read_bytes() for p in output.glob('inventory*')}, before)
            with patch.object(direct, 'load_env', side_effect=AssertionError('offline credentials')):
                latest = setup.load_latest(output, root, 'test-agent')
            for selection in ({}, {'device': '192.0.2.1'}, {'index': 'logs-a'},
                    {'index': 'logs-a', 'field': 'deviceAddress'}):
                view = setup.project(latest, **selection)
                self.assertFalse(view['query_ready'])
                self.assertEqual(view['setup_status'], 'needs_attention')
                self.assertEqual(view['last_attempt']['status'], 'failed')
                self.assertEqual(view['last_success'], success['last_success'])
            recovered = setup.execute(profile, capture())
            self.assertTrue(recovered['query_ready'])
            self.assertEqual(recovered['last_attempt']['status'], 'completed')

    def test_first_and_later_local_preparation_failures_are_recorded_without_secrets(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            profile = self.profile({'mode': 'es-api', 'connection_ref': 'direct',
                'output_dir': 'agent', 'env_file': str(root / 'missing.env'),
                'index_patterns': ['logs-*']}, root)
            with self.assertRaises(FileNotFoundError):
                setup.execute(profile)
            output = Path(profile['output_dir'])
            first = json.loads((output / 'setup.json').read_text())
            self.assertIsNone(first['source'])
            self.assertIsNone(first['last_success'])
            self.assertEqual(first['last_attempt']['status'], 'failed')
            self.assertFalse(first['query_ready'])
            with self.assertRaises(ValueError):
                setup.load_latest(output, root, 'test-agent')
            native = {**profile, 'mode': 'mcp-native', 'connection_ref': 'fixture-mcp'}
            success = setup.execute(native, capture())
            before = {p.name: p.read_bytes() for p in output.glob('inventory*')}
            with patch.object(direct, 'load_env', side_effect=RuntimeError('synthetic-secret')):
                with self.assertRaises(RuntimeError):
                    setup.execute(profile)
            failed = json.loads((output / 'setup.json').read_text())
            self.assertEqual(failed['source'], success['source'])
            self.assertEqual(failed['profile'], success['profile'])
            self.assertEqual(failed['last_success'], success['last_success'])
            self.assertFalse(failed['query_ready'])
            self.assertNotIn('synthetic-secret', json.dumps(failed))
            self.assertEqual({p.name: p.read_bytes() for p in output.glob('inventory*')}, before)

    def test_first_http_transport_failure_is_recorded(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            profile = self.profile({'mode': 'mcp-http', 'connection_ref': 'fixture-mcp',
                'output_dir': 'agent', 'url': 'https://mcp.example.test/mcp', 'auth': 'none'}, root)
            client = Mock()
            client.initialize.side_effect = mcp.MCPError('synthetic-secret')
            with patch.object(mcp, 'http_client', return_value=client):
                with self.assertRaises(mcp.MCPError):
                    setup.execute(profile)
            state = json.loads((Path(profile['output_dir']) / 'setup.json').read_text())
            self.assertEqual(state['last_attempt']['status'], 'failed')
            self.assertFalse(state['query_ready'])
            self.assertIsNone(state['last_success'])
            self.assertNotIn('synthetic-secret', json.dumps(state))

    def test_source_conflict_and_lock_refusal_preserve_every_data_file(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            profile = self.profile({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                'output_dir': 'agent'}, root)
            setup.execute(profile, capture())
            output = Path(profile['output_dir'])
            before = {p.name: p.read_bytes() for p in output.iterdir() if p.name != '.write.lock'}
            with patch.object(mcp, 'from_capture') as scan:
                with self.assertRaises(direct.ConfigError):
                    setup.execute({**profile, 'connection_ref': 'other'}, capture())
                with setup.output_lock(profile):
                    with self.assertRaises(direct.ConfigError):
                        setup.execute(profile, capture())
                scan.assert_not_called()
            self.assertEqual({p.name: p.read_bytes() for p in output.iterdir() if p.name != '.write.lock'}, before)

    def test_offline_source_swap_and_legacy_unbound_state_require_explicit_setup(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            profile = self.profile({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                'output_dir': 'agent'}, root)
            setup.execute(profile, capture())
            output = Path(profile['output_dir'])
            report_file = output / 'inventory.json'
            original_report = report_file.read_bytes()
            report = json.loads(original_report)
            report['source']['connection_ref'] = 'other'
            report_file.write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                setup.load_latest(output, root, 'test-agent')
            report_file.write_bytes(original_report)
            state_file = output / 'setup.json'
            legacy = json.loads(state_file.read_text())
            legacy['schema_version'] = 2
            legacy.pop('source')
            state_file.write_text(json.dumps(legacy))
            with self.assertRaises(ValueError):
                setup.load_latest(output, root, 'test-agent')
            with patch.object(mcp, 'from_capture', side_effect=mcp.MCPError('failed')):
                with self.assertRaises(mcp.MCPError):
                    setup.execute(profile, capture())
            failed = json.loads(state_file.read_text())
            self.assertIsNone(failed['last_success'])
            self.assertIsNone(failed['verified_at'])
            with self.assertRaises(ValueError):
                setup.load_latest(output, root, 'test-agent')
            self.assertEqual(report_file.read_bytes(), original_report)
            self.assertTrue(setup.execute(profile, capture())['query_ready'])

    def test_not_ready_partial_refresh_does_not_rewrite_success_summary(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            profile = self.profile({'mode': 'mcp-native', 'connection_ref': 'fixture-mcp',
                'output_dir': 'agent'}, root)
            success = setup.execute(profile, capture())
            not_ready = capture()
            not_ready['records'][0]['search_result']['timed_out'] = True
            failed = setup.execute(profile, not_ready)
            self.assertFalse(failed['query_ready'])
            self.assertEqual(failed['last_attempt']['status'], 'completed')
            self.assertEqual(failed['last_success'], success['last_success'])
            self.assertEqual(failed['verified_at'], success['verified_at'])
            self.assertNotIn('stem', json.dumps(failed['last_success']))


if __name__ == '__main__':
    unittest.main()
