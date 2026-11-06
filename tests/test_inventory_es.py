"""Skill-owned offline tests: no deployment settings, network, or MCP server import."""
import contextlib
import io
import runpy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('inventory_es', SCRIPTS / 'inventory_es.py')
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)
READ_SPEC = importlib.util.spec_from_file_location('read_inventory',
    SCRIPTS / 'es.py')
reader = importlib.util.module_from_spec(READ_SPEC)
READ_SPEC.loader.exec_module(reader)
TEST_ROOT = os.environ.get('INVENTORY_TEST_TMP')


class ScanES:
    """A tiny synthetic index; never creates a network connection."""
    def __init__(self, url, key, ca=None, connect_ip=None, max_requests=1500):
        self.url = urlsplit(url)
        self.requests = 0
        self.max_requests = max_requests

    def request(self, method, path, body=None):
        self.requests += 1
        if path.startswith('/_resolve/index/'):
            return {'indices': [{'name': 'logstash-test'}]}
        if '_field_caps' in path:
            return {'fields': {}}
        return {'hits': {'total': {'value': 7, 'relation': 'eq'}}}


class FakeES:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = []

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        return next(self.pages)


def field(kind='keyword', aggregatable=True):
    return {kind: {'aggregatable': aggregatable, 'searchable': True}}


def summary(count=3):
    return {'hits': {'total': {'value': count, 'relation': 'eq'}},
        'aggregations': {'presence': {'buckets': {'deviceAddress': {'doc_count': 2}}}}}


class InventoryTests(unittest.TestCase):
    def test_device_identity_never_falls_back_to_traffic_or_agent_ip(self):
        es = FakeES([{'fields': {'sourceAddress': field('ip'), 'agentAddress': field('ip')}}, summary()])
        result = inventory.scan_index(es, 'logstash-test')
        self.assertEqual(result['identity_observations'], [])
        self.assertEqual(inventory.merge_devices([result]), [])
        self.assertIsNone(result['identity_fields']['deviceAddress'])

    def test_paginates_using_returned_after_key_and_keeps_missing_identity(self):
        es = FakeES([{'fields': {'deviceAddress': field('ip'), 'deviceVendor': field()}}, summary(),
            {'aggregations': {'identities': {'buckets': [{'key': {'deviceAddress': '192.0.2.1',
                'deviceVendor': 'VendorA'}, 'doc_count': 2}], 'after_key': {'deviceAddress': 'cursor'}}}},
            {'aggregations': {'identities': {'buckets': [{'key': {'deviceAddress': None,
                'deviceVendor': 'VendorB'}, 'doc_count': 1}]}}}])
        result = inventory.scan_index(es, 'logstash-test')
        self.assertEqual(result['identity_status'], 'complete')
        self.assertEqual(es.calls[3][2]['aggs']['identities']['composite']['after'], {'deviceAddress': 'cursor'})
        devices = inventory.merge_devices([result])
        self.assertEqual([d['deviceAddress'] for d in devices], ['192.0.2.1'])
        self.assertEqual(result['missing_deviceAddress_documents'], 1)
        self.assertNotIn('_source', es.calls[2][2])
        self.assertEqual(es.calls[2][2]['size'], 0)

    def test_page_limit_is_partial_not_a_complete_device_list(self):
        es = FakeES([{'fields': {'deviceAddress': field('ip')}}, summary(),
            {'aggregations': {'identities': {'buckets': [{'key': {'deviceAddress': '192.0.2.1'},
                'doc_count': 2}], 'after_key': {'deviceAddress': 'cursor'}}}}])
        result = inventory.scan_index(es, 'logstash-test', max_pages=1)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['identity_status'], 'page_limit_reached')

    def test_unknown_field_type_is_not_used_for_aggregation(self):
        self.assertIsNone(inventory.pick_field({'deviceAddress': field('text', False)}, 'deviceAddress'))
        self.assertEqual(inventory.pick_field({'deviceAddress.keyword': field()}, 'deviceAddress'), 'deviceAddress.keyword')

    def test_unindexed_error_payload_has_no_empty_filters_aggregation(self):
        es = FakeES([{'fields': {'_index': field()}},
            {'hits': {'total': {'value': 7, 'relation': 'eq'}}, 'aggregations': {}}])
        result = inventory.scan_index(es, 'logstash-error-test')
        self.assertEqual(es.calls[1][2]['aggs'], {})
        self.assertEqual(result['document_count'], 7)
        self.assertEqual(result['missing_deviceAddress_documents'], 7)
        self.assertEqual(result['identity_status'], 'no_aggregatable_CEF_identity_fields')

    def test_env_file_does_not_execute_shell_substitutions(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            path = Path(folder) / 'example.env'
            path.write_text('IGNORED="$(touch should-not-exist)"\n')
            self.assertEqual(inventory.load_env(path)['IGNORED'], '$(touch should-not-exist)')
            self.assertFalse((Path(folder) / 'should-not-exist').exists())

    def test_write_endpoint_rejected_before_any_network(self):
        es = inventory.ES('https://es.example.test:9200', 'synthetic-key')
        with self.assertRaisesRegex(ValueError, 'read-only'):
            es.request('DELETE', '/logstash-test')

    def test_backend_direct_execution_refuses_even_while_public_operation_is_locked(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            root = Path(folder)
            profile = reader.validate({'mode': 'es-api', 'connection_ref': 'direct',
                'repo_root': str(root), 'agent_id': 'agent', 'output_dir': 'agent',
                'env_file': str(root / 'missing.env'), 'index_patterns': ['logs-*']}, root)
            with reader.output_lock(profile), patch.object(inventory, 'load_env') as load, \
                    patch('socket.create_connection', side_effect=AssertionError('backend attempted network')), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    runpy.run_path(str(SCRIPTS / 'inventory_es.py'), run_name='__main__')
            self.assertNotEqual(stopped.exception.code, 0)
            load.assert_not_called()
            self.assertFalse((Path(profile['output_dir']) / 'inventory.json').exists())

    def test_shared_skill_output_and_symlink_to_it_are_rejected(self):
        skill = Path(inventory.__file__).resolve().parents[1]
        with self.assertRaises(inventory.ConfigError):
            inventory.output_directory(skill / 'references' / 'inventory')
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            link = Path(folder) / 'shared-skill'
            link.symlink_to(skill, target_is_directory=True)
            with self.assertRaises(inventory.ConfigError):
                inventory.output_directory(link / 'references' / 'inventory')

    def test_two_agents_write_separate_reports_without_secrets(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            repo = Path(folder)
            config = repo / 'synthetic.env'
            config.write_text('ES_URL=https://es.example.test:9200\n'
                'ES_API_KEY=synthetic-secret-never-publish\nES_INDEX_PATTERNS=logstash-*\n')
            for agent in ('agent-a', 'agent-b'):
                output = repo / agent
                profile = reader.validate({'mode': 'es-api', 'connection_ref': 'direct',
                    'env_file': str(config), 'output_dir': str(output), 'repo_root': str(repo),
                    'agent_id': agent, 'index_patterns': ['logstash-*']}, repo)
                with patch.object(reader.direct, 'ES', ScanES), patch('builtins.print'), patch.object(inventory.time, 'sleep'):
                    self.assertTrue(reader.execute(profile)['query_ready'])
                report = json.loads((output / 'inventory.json').read_text())
                self.assertEqual(report['source']['es_url'], 'https://es.example.test:9200')
                self.assertEqual(report['source']['index_patterns'], ['logstash-*'])
                self.assertEqual(report['schema_version'], 2)
                for name in ('inventory.json', 'inventory.md', 'setup.json'):
                    self.assertNotIn('synthetic-secret', (output / name).read_text())
            self.assertTrue((repo / 'agent-a' / 'inventory.md').is_file())
            self.assertTrue((repo / 'agent-b' / 'inventory.md').is_file())

    def test_explicit_file_cannot_be_overridden_or_mixed_with_process_settings(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            path = Path(folder) / 'inventory.env'
            path.write_text('ES_URL=https://intended.example.test\nES_INDEX_PATTERNS=logs-*\n')
            with patch.dict(os.environ, {'ES_URL': 'https://stale.example.test',
                    'ES_API_KEY': 'stale-key', 'ES_CA_CERT': '/stale-ca'}, clear=True):
                config = inventory.load_env(path)
            self.assertEqual(config['ES_URL'], 'https://intended.example.test')
            self.assertNotIn('ES_API_KEY', config)
            self.assertNotIn('ES_CA_CERT', config)

    def test_nonaggregatable_device_address_does_not_claim_complete(self):
        es = FakeES([{'fields': {'deviceAddress': field('text', False)}},
            {'hits': {'total': {'value': 5, 'relation': 'eq'}},
             'aggregations': {'presence': {'buckets': {'deviceAddress': {'doc_count': 5}}}}}])
        result = inventory.scan_index(es, 'logstash-test')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['identity_status'], 'deviceAddress_not_aggregatable')
        self.assertEqual(result['missing_deviceAddress_documents'], 0)
        self.assertEqual(inventory.merge_devices([result]), [])

    def test_different_or_unidentified_existing_source_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            output = Path(folder)
            source = {'es_url': 'https://current.example.test', 'index_patterns': ['logstash-*']}
            for existing in ({'source': {'es_url': 'https://other.example.test'}}, {}, []):
                previous = output / 'inventory.json'
                previous.write_text(json.dumps(existing))
                original = previous.read_bytes()
                with self.assertRaises(inventory.ConfigError):
                    inventory.check_output_source(output, source)
                self.assertEqual(previous.read_bytes(), original)

    def test_partial_refresh_preserves_last_complete_report(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            output = Path(folder)
            report = {'source': {'es_url': 'https://es.example.test'}, 'status': 'complete',
                'finished_at': '2026-11-01T00:00:00Z', 'patterns': ['logstash-*'],
                'indices': [], 'errors': [], 'devices': []}
            self.assertEqual(inventory.publish_report(output, report), 'inventory')
            original = {name: (output / name).read_bytes()
                for name in ('inventory.md', 'inventory.json')}
            report['status'] = 'partial'
            report['errors'] = [{'index': 'logstash-test', 'error': 'request_budget_exhausted'}]
            self.assertEqual(inventory.publish_report(output, report), 'inventory.partial')
            for name, content in original.items():
                self.assertEqual((output / name).read_bytes(), content)
            self.assertEqual(json.loads((output / 'inventory.partial.json').read_text())['status'], 'partial')

    def test_backend_cli_never_reads_even_explicit_settings(self):
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            output = Path(folder) / 'new-agent'
            result = subprocess.run([sys.executable, '-B', str(SCRIPTS / 'inventory_es.py'),
                '--env-file', str(Path(folder) / 'missing.env'), '--output-dir', str(output)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('es.py setup', result.stdout)
            self.assertFalse(output.exists())

    def test_configuration_and_authentication_errors_do_not_echo_values(self):
        with self.assertRaises(inventory.ConfigError) as error:
            inventory.ES('https://user:secret@es.example.test', 'synthetic-key')
        self.assertNotIn('secret', inventory.safe_error(error.exception))
        self.assertIn('401', inventory.safe_error(RuntimeError('elasticsearch_http_401')))
        self.assertIn('403', inventory.safe_error(RuntimeError('elasticsearch_http_403')))
        self.assertEqual(inventory.safe_error(ValueError('synthetic-secret')), 'ValueError')
        for code in ('mcp_http_401', 'mcp_http_403', 'mcp_search_schema_unsupported',
                'mcp_connection_failed', 'mcp_tool_failed'):
            self.assertEqual(inventory.safe_error(RuntimeError(code + '；synthetic-secret')), code)
        for message in ('synthetic-secret', 'mcp_synthetic_secret', 'mcp_http_401synthetic-secret'):
            self.assertEqual(inventory.safe_error(RuntimeError(message)), 'operation_failed')

    def test_offline_reader_only_returns_requested_device_index_or_field(self):
        report = {'source': {'es_url': 'https://es.example.test'}, 'status': 'complete',
            'devices': [{'deviceAddress': '192.0.2.1', 'indices': ['logstash-test']},
                {'deviceAddress': '192.0.2.2', 'indices': ['logstash-other']}],
            'indices': [{'index': 'logstash-test', 'fields': {'deviceAddress': field('ip')},
                'identity_observations': ['large-observations'], 'field_presence': {'deviceAddress': 5}}]}
        result = reader.project(report, device='192.0.2.1')
        self.assertEqual(len(result['devices']), 1)
        self.assertNotIn('192.0.2.2', json.dumps(result))
        result = reader.project(report, index='logstash-test')
        self.assertNotIn('fields', result['indices'][0])
        self.assertNotIn('identity_observations', result['indices'][0])
        result = reader.project(report, index='logstash-test', field='deviceAddress')
        self.assertEqual(result['indices'][0]['capabilities'], field('ip'))
        self.assertEqual(result['indices'][0]['indexed_documents'], 5)

    def test_reader_cli_reads_agent_directory_without_printing_entire_fields(self):
        script = str(Path(reader.__file__).resolve())
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            repo = Path(folder) / 'repo'
            output = repo / '.local' / 'elasticsearch-query' / 'agent-example' / 'source-a'
            output.mkdir(parents=True)
            report = {'source': {'es_url': 'https://es.example.test'}, 'status': 'partial',
                'scope': {'repo_root': str(repo.resolve()), 'agent_id': 'agent-example'},
                'devices': [], 'indices': [{'index': 'logstash-test',
                    'fields': {'deviceAddress': field('ip'), 'unrelated': field()},
                    'field_presence': {'deviceAddress': 2}}]}
            (output / 'inventory.partial.json').write_text(json.dumps(report))
            (output / 'setup.json').write_text(json.dumps({'schema_version': 3, 'scope': report['scope'], 'source': report['source'],
                'inventory_report_stem': 'inventory.partial'}))
            result = subprocess.run([sys.executable, '-B', script, 'inventory', '--input-dir', str(output),
                '--repo-root', str(repo), '--agent-id', 'agent-example',
                '--index', 'logstash-test', '--field', 'deviceAddress'],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            projected = json.loads(result.stdout)
            self.assertEqual(projected['status'], 'partial')
            self.assertEqual(projected['indices'][0]['indexed_documents'], 2)
            self.assertNotIn('unrelated', result.stdout)

    def test_reader_cli_rejects_field_without_index(self):
        result = subprocess.run([sys.executable, '-B', str(Path(reader.__file__).resolve()), 'inventory',
            '--input-dir', 'unused', '--repo-root', '.', '--agent-id', 'agent-example',
            '--field', 'deviceAddress'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--field requires --index', result.stderr)


if __name__ == '__main__':
    unittest.main()
