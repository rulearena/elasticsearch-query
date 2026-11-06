#!/usr/bin/env python3
"""MCP-only inventory. No Elasticsearch credentials or direct-ES fallback."""
import datetime as dt
import fnmatch
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from inventory_es import (ConfigError, IDENTITY, IMPORTANT, load_env, merge_devices,
    now, pick_field)

LIMIT = 8 * 1024 * 1024
LOGICAL_TOOLS = ('list_indices', 'get_mapping', 'search_events')


class MCPError(RuntimeError):
    """Only fixed diagnostic codes, never response text or credentials."""


def validate_token_name(name):
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Z_][A-Z0-9_]*', name)
            or name in ('ES_API_KEY', 'ELASTICSEARCH_API_KEY')):
        raise ConfigError('token_env 請填 MCP Token 的環境變數名稱，例如 ES_MCP_TOKEN；不能填佔位符、Bearer 字串或 ES API Key。')


def resolve_token(value, values, environment):
    """Resolve only explicit ${NAME} references. Never evaluate shell expressions."""
    seen = set()
    for _ in range(8):
        if not isinstance(value, str) or not value.strip():
            raise ConfigError('缺少 MCP 認證；請配置指定的 MCP Token 環境變數，不需要 ES Key。')
        value = value.strip()
        if value.lower().startswith('bearer '):
            value = value[7:].strip()
        match = re.fullmatch(r'\$\{([A-Z_][A-Z0-9_]*)\}', value)
        if match:
            name = match[1]
            validate_token_name(name)
            if name in seen:
                raise ConfigError('MCP Token 佔位符循環引用；請修正執行環境，不要貼出 Token。')
            seen.add(name)
            replacement = values.get(name)
            if not replacement or replacement == value:
                replacement = environment.get(name)
            value = replacement
            continue
        if any(marker in value for marker in ('${', '$(', '`', '\r', '\n')):
            raise ConfigError('MCP Token 有未解析的佔位符或不支援的表示式；只支援 ${變數名稱}，不執行 shell。')
        if value.upper().startswith('REPLACE_'):
            raise ConfigError('MCP Token 仍是範例值；請在執行環境設定，不要貼到聊天。')
        return value
    raise ConfigError('MCP Token 佔位符引用過深，請簡化設定。')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_endpoint_security(url, authenticated):
    """Only allow cleartext MCP on loopback, and never send a bearer token over it."""
    try:
        parsed = urlsplit(url)
        parsed.port
    except ValueError:
        raise ConfigError('MCP 網址格式錯誤。') from None
    if parsed.scheme == 'https':
        return
    if parsed.scheme != 'http' or not parsed.hostname:
        raise ConfigError('MCP 網址必須使用 HTTPS；HTTP 僅允許本機回環連線。')
    host = parsed.hostname.lower().rstrip('.')
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == 'localhost'
    if not loopback:
        raise ConfigError('遠端 MCP 必須使用 HTTPS。')
    if authenticated:
        raise ConfigError('MCP Token 不可透過未加密的 HTTP 傳送；請改用 HTTPS 或本機無認證連線。')


def unwrap(value):
    if not isinstance(value, dict) or value.get('isError'):
        raise MCPError('mcp_tool_failed；請核對 MCP 工具與 server 端授權，不需提供 ES Key。')
    if 'structuredContent' in value:
        result = value['structuredContent']
    else:
        blocks = [c['text'] for c in value.get('content', []) if c.get('type') == 'text']
        if len(blocks) != 1:
            raise MCPError('mcp_result_format_unsupported')
        result = json.loads(blocks[0])
    if isinstance(result, dict) and set(result) == {'result'}:
        result = result['result']
    return result


class HTTPMCP:
    def __init__(self, url, token=None, ca=None, max_requests=1000):
        validate_endpoint_security(url, bool(token))
        parsed = urlsplit(url)
        if (not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ConfigError('請提供不含帳密、Token 或查詢參數的 MCP HTTP(S) 網址。')
        if token:
            token = resolve_token(token, {}, {})
        self.url, self.sequence, self.requests = url, 0, 0
        self.max_requests = max_requests
        self.headers = {'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream', 'Accept-Encoding': 'identity'}
        if token:
            self.headers['Authorization'] = 'Bearer ' + token
        self.opener = urllib.request.build_opener(NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
        self.allowed = set()

    def rpc(self, method, params=None, notification=False):
        if self.requests >= self.max_requests:
            raise MCPError('mcp_request_budget_exhausted')
        self.requests += 1
        payload = {'jsonrpc': '2.0', 'method': method}
        if not notification:
            self.sequence += 1
            payload['id'] = self.sequence
        if params is not None:
            payload['params'] = params
        request = urllib.request.Request(self.url, json.dumps(payload).encode(), self.headers, method='POST')
        try:
            with self.opener.open(request, timeout=25) as response:
                session = response.headers.get('Mcp-Session-Id')
                if session:
                    self.headers['Mcp-Session-Id'] = session
                if response.headers.get('Content-Encoding', '').lower() not in ('', 'identity'):
                    raise MCPError('mcp_compressed_response_rejected')
                if response.status == 202 and notification:
                    return {}
                if 'text/event-stream' in response.headers.get('Content-Type', ''):
                    value = self.read_sse(response, payload.get('id'))
                else:
                    raw = response.read(LIMIT + 1)
                    if len(raw) > LIMIT:
                        raise MCPError('mcp_response_too_large')
                    value = json.loads(raw)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            hints = {401: '請配置有效的 MCP 認證；不是 ES Key。',
                403: '請核對 MCP 存取權限。', 404: '請核對 MCP endpoint 或 session。'}
            raise MCPError('mcp_http_' + str(status) + '；' + hints.get(status, '請核對 MCP 服務。')) from None
        except urllib.error.URLError:
            raise MCPError('mcp_connection_failed；請核對 MCP 網址、CA 與網路。') from None
        if not isinstance(value, dict) or 'error' in value or value.get('id') != payload.get('id'):
            raise MCPError('mcp_rpc_failed')
        return value.get('result', {})

    @staticmethod
    def read_sse(response, request_id):
        size, data = 0, []
        while True:
            raw = response.readline(LIMIT + 1)
            size += len(raw)
            if size > LIMIT:
                raise MCPError('mcp_response_too_large')
            if not raw:
                raise MCPError('mcp_stream_ended_without_response')
            line = raw.decode('utf-8').rstrip('\r\n')
            if line.startswith('data:'):
                data.append(line[5:].lstrip())
            elif not line and data:
                value = json.loads('\n'.join(data))
                data = []
                if isinstance(value, dict) and value.get('id') == request_id:
                    return value

    def initialize(self):
        result = self.rpc('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
            'clientInfo': {'name': 'elasticsearch-query', 'version': '1.0.0'}})
        self.headers['MCP-Protocol-Version'] = result['protocolVersion']
        self.rpc('notifications/initialized', notification=True)
        found, cursor = [], None
        for _ in range(20):
            result = self.rpc('tools/list', {'cursor': cursor} if cursor else {})
            found.extend(result.get('tools', []))
            following = result.get('nextCursor')
            if not following:
                return found
            if following == cursor:
                break
            cursor = following
        raise MCPError('mcp_tool_list_incomplete')

    def call(self, name, arguments):
        if name not in self.allowed:
            raise MCPError('mcp_tool_outside_readonly_tools')
        return unwrap(self.rpc('tools/call', {'name': name, 'arguments': arguments}))


def tool_map(tools):
    selected = {}
    for logical in LOGICAL_TOOLS:
        candidates = [t for t in tools if t.get('name') == logical or
            t.get('name', '').endswith(('_' + logical, '/' + logical, ':' + logical))]
        if len(candidates) > 1:
            raise ConfigError('找到多組 MCP 盤點工具；請只選定一個已授權的 MCP 來源。')
        if candidates:
            selected[logical] = candidates[0]
    if 'list_indices' not in selected:
        raise MCPError('mcp_missing_list_indices；請確認所選 MCP 工具，不需改交 ES Key。')
    return selected


def names_from(result):
    if isinstance(result, dict):
        result = result.get('indices')
    if not isinstance(result, list) or not all(isinstance(n, str) for n in result):
        raise MCPError('mcp_index_list_format_unsupported')
    return sorted(set(n for n in result if not n.startswith('.')))


def window(profile):
    if profile.get('start') or profile.get('end'):
        try:
            start, end = (dt.datetime.fromisoformat(profile[n].replace('Z', '+00:00')) for n in ('start', 'end'))
        except (ValueError, KeyError):
            raise ConfigError('start、end 需同時提供，使用含時區的 ISO 時間。') from None
    else:
        end = dt.datetime.now(dt.timezone.utc)
        start = end - dt.timedelta(hours=profile.get('lookback_hours', 24))
    if start.utcoffset() is None or end.utcoffset() is None or not dt.timedelta(0) < end-start <= dt.timedelta(hours=24):
        raise ConfigError('此 MCP 盤點查詢視窗須含時區，且大於 0、最多 24 小時。')
    return start.isoformat(), end.isoformat()


def index_window(profile, index, fallback):
    """Use index dates only after their UTC-day convention was confirmed."""
    if profile.get('index_date_timezone') == 'UTC' and not profile.get('start'):
        match = re.search(r'-(\d{8})$', index)
        if match:
            try:
                start = dt.datetime.strptime(match[1], '%Y%m%d').replace(tzinfo=dt.timezone.utc)
                return start.isoformat(), (start + dt.timedelta(days=1)).isoformat()
            except ValueError:
                pass
    return fallback


def search_arguments(request, schema):
    properties = schema.get('properties', {})
    core = {'index', 'start', 'end', 'fields', 'limit'}
    if not core <= properties.keys() or 'query' in request:
        raise MCPError('mcp_search_schema_unsupported')
    arguments = dict(request)
    if 'filters' not in properties and arguments.get('filters') == {}:
        arguments.pop('filters')
    if 'time_field' not in properties and arguments.get('time_field') == '@timestamp':
        arguments.pop('time_field')
    if set(arguments) - properties.keys() or set(schema.get('required', [])) - arguments.keys():
        raise MCPError('mcp_search_schema_unsupported')
    return arguments


def record_from(index, mapping, search, start, end, aggregate_field=None):
    fields = mapping.get('fields', {})
    record = {'index': index, 'status': 'partial', 'scanned_at': now(),
        'document_count': None, 'time_field': '@timestamp' if '@timestamp' in fields else None,
        'time_range': {'first': None, 'last': None}, 'field_count': len(fields), 'fields': fields,
        'field_presence': {}, 'identity_fields': {n: pick_field(fields, n) for n in IDENTITY},
        'missing_deviceAddress_documents': None, 'identity_observations': [], 'identity_pages': 0,
        'identity_status': 'sample_and_top_terms_only', 'query_window': {'start': start, 'end': end},
        'window_document_count': None, 'field_value_evidence': {}, 'value_examples': {}}
    if search is None:
        record['identity_status'] = 'metadata_only'
        return record
    shards = search.get('shards', search.get('_shards'))
    if (search.get('timed_out') is not False or not isinstance(shards, dict)
            or shards.get('failed') != 0):
        raise MCPError('mcp_search_incomplete_or_missing_metadata')
    hits = search.get('hits', {})
    total = hits.get('total', {})
    if (not isinstance(total, dict) or total.get('relation') not in ('eq', 'gte')
            or type(total.get('value')) is not int or total['value'] < 0):
        raise MCPError('mcp_search_missing_count_metadata')
    record['window_document_count'] = total
    observations = {}
    for hit in hits.get('hits', []):
        source = hit.get('_source', {})
        # Persist evidence of value presence, not raw logs or arbitrary source payloads.
        for name in IMPORTANT:
            if name in source and source[name] is not None:
                record['field_value_evidence'][name] = 'observed_in_sample'
        address = source.get('deviceAddress')
        if not isinstance(address, str):
            continue
        identity = {n: source.get(n) if isinstance(source.get(n), str) else None for n in IDENTITY}
        key = tuple(identity[n] for n in IDENTITY)
        observations[key] = {**identity, 'document_count': None, 'time_range': {'first': None, 'last': None}}
    top = (search.get('aggregations', {}).get('top_values')
        if aggregate_field and aggregate_field == record['identity_fields']['deviceAddress'] else None)
    if top is not None:
        record['value_examples']['deviceAddress'] = top
        for bucket in top.get('buckets', []):
            address = bucket.get('key')
            if isinstance(address, str) and not any(k[0] == address for k in observations):
                observations[(address, None, None, None)] = {'deviceAddress': address,
                    'deviceVendor': None, 'deviceProduct': None, 'deviceHostName': None,
                    'document_count': None, 'time_range': {'first': None, 'last': None}}
    record['identity_observations'] = list(observations.values())
    return record


def make_report(profile, tools, indices, records, errors, unscanned, started):
    source = {'transport': 'mcp', 'connection_ref': profile['connection_ref'],
        'index_patterns': profile['index_patterns']}
    if profile.get('url'):
        source['mcp_url'] = profile['url']
    return {'schema_version': 3, 'source': source,
        'scope': {'repo_root': profile.get('repo_root'), 'agent_id': profile.get('agent_id')},
        'configuration': 'agent-profile',
        'started_at': started, 'finished_at': now(), 'patterns': profile['index_patterns'],
        'status': 'partial', 'resolved_index_count': len(indices), 'not_scanned_indices': unscanned,
        'excluded_aliases': [], 'excluded_data_streams': [], 'indices': records,
        'devices': merge_devices(records), 'errors': errors, 'http_requests': None,
        'query_ready': any(r.get('window_document_count') is not None for r in records),
        'coverage': {'indices': 'authorized_visible_names; aliases may overlap',
            'fields': 'field_caps', 'devices': 'observed_samples_and_top_terms_in_query_window',
            'field_presence': 'sample_evidence_only; exact counts unavailable',
            'missing_capabilities': ['full_identity_pagination', 'exact_field_presence_counts',
                'all_retained_data_time_range_and_counts']},
        'mcp_tools': {k: v['name'] for k, v in tool_map(tools).items()}}


def scan_client(client, profile):
    started = now()
    tools = client.initialize()
    selected = tool_map(tools)
    client.allowed = {t['name'] for t in selected.values()}
    indices = names_from(client.call(selected['list_indices']['name'], {}))
    indices = [n for n in indices if any(fnmatch.fnmatchcase(n, p) for p in profile['index_patterns'])]
    fallback = window(profile)
    records, errors = [], []
    limit = profile.get('max_indices', len(indices))
    for number, index in enumerate(indices[:limit], 1):
        start, end = index_window(profile, index, fallback)
        try:
            if 'get_mapping' not in selected:
                raise MCPError('mcp_missing_get_mapping')
            mapping = client.call(selected['get_mapping']['name'], {'index': index})
            result, args = None, {}
            if 'search_events' in selected:
                try:
                    fields = mapping.get('fields', {})
                    chosen = [name for name in IMPORTANT if name in fields]
                    if not chosen:
                        raise MCPError('no_known_indexed_cef_fields')
                    schema = selected['search_events'].get('inputSchema', {})
                    request = {'index': index, 'start': start, 'end': end,
                        'fields': chosen, 'limit': 3, 'filters': {}, 'time_field': '@timestamp'}
                    address = pick_field(fields, 'deviceAddress')
                    if address and 'aggregate_field' in schema.get('properties', {}):
                        request['aggregate_field'] = address
                    args = search_arguments(request, schema)
                    result = client.call(selected['search_events']['name'], args)
                except MCPError as exc:
                    errors.append({'index': index, 'error': str(exc)})
            try:
                records.append(record_from(index, mapping, result, start, end, args.get('aggregate_field')))
            except MCPError as exc:
                errors.append({'index': index, 'error': str(exc)})
                records.append(record_from(index, mapping, None, start, end))
        except MCPError as exc:
            errors.append({'index': index, 'error': str(exc)})
        print('MCP ' + str(number) + '/' + str(min(limit, len(indices))) + ' ' + index, flush=True)
    report = make_report(profile, tools, indices, records, errors, indices[limit:], started)
    report['http_requests'] = client.requests
    return report


def from_capture(profile, capture):
    if capture.get('connection_ref') != profile['connection_ref']:
        raise ConfigError('原生 MCP capture 的來源與 profile 不同。')
    tools = capture['tools']
    tool_map(tools)
    indices = names_from(capture['indices_result'])
    indices = [n for n in indices if any(fnmatch.fnmatchcase(n, p) for p in profile['index_patterns'])]
    records, errors, seen = [], [], set()
    limit = profile.get('max_indices', len(indices))
    scan_indices = set(indices[:limit])
    for row in capture.get('records', []):
        index = row['index']
        if index not in scan_indices or index in seen:
            raise ConfigError('capture 有重複或未列入授權索引清單的紀錄。')
        seen.add(index)
        try:
            start, end = window({'start': row['start'], 'end': row['end']})
            records.append(record_from(index, row['mapping_result'], row.get('search_result'), start, end,
                row.get('aggregate_field')))
        except MCPError as exc:
            errors.append({'index': index, 'error': str(exc)})
            records.append(record_from(index, row['mapping_result'], None, start, end))
    return make_report(profile, tools, indices, records, errors,
        sorted(set(indices) - seen), capture.get('started_at', now()))


def http_client(profile):
    token_name = profile.get('token_env', 'MCP_TOKEN')
    validate_token_name(token_name)
    values = load_env(Path(profile['env_file'])) if profile.get('env_file') else os.environ
    token = None
    if profile.get('auth', 'bearer') == 'bearer':
        token = resolve_token(values.get(token_name), values, os.environ)
    return HTTPMCP(profile['url'], token, profile.get('ca_file'), profile.get('max_requests', 1000))
