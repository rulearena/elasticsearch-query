#!/usr/bin/env python3
"""Portable skill-owned CEF inventory; standard library only, no raw events."""
import datetime as dt
import fnmatch
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import tempfile
import time
from urllib.parse import quote, urlsplit

IDENTITY = ('deviceAddress', 'deviceVendor', 'deviceProduct', 'deviceHostName')
IMPORTANT = IDENTITY + ('agentAddress', 'sourceAddress', 'destinationAddress',
    'deviceAction', 'event.action', 'name', 'deviceEventClassId',
    'deviceReceiptTime', 'startTime', 'endTime', '@timestamp')


class ConfigError(ValueError):
    """Actionable configuration errors with fixed, credential-free messages."""


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_env(path):
    """Use the explicit file exclusively, or process settings when no file is given."""
    values = {}
    if path:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('export '):
                line = line[7:]
            key, sep, value = line.partition('=')
            if not sep:
                raise ConfigError('設定檔格式錯誤；每行需為 NAME=value。')
            try:
                parts = shlex.split(value, comments=True)
            except ValueError:
                raise ConfigError('設定檔引號不完整；請檢查設定檔，不需貼出金鑰。') from None
            if len(parts) > 1:
                raise ConfigError('設定值包含空白時，請用引號包住。')
            values[key.strip()] = parts[0] if parts else ''
    else:
        for key in ('ES_URL', 'ES_API_KEY', 'ES_INDEX_PATTERNS', 'ES_CA_CERT'):
            if key in os.environ:
                values[key] = os.environ[key]
    return values


def output_directory(path):
    """Never write runtime data through a link into the shared skill package."""
    target = path.expanduser().resolve()
    skill = Path(__file__).resolve().parents[1]
    if target == skill or skill in target.parents:
        raise ConfigError('請將 --output-dir 指向此 Agent 專用、且位於共用 skill 以外的目錄。')
    return target


def execution_scope(repo_root, agent_id, output):
    root = Path(repo_root).expanduser().resolve()
    if not root.is_dir():
        raise ConfigError('repo_root 必須是目前已授權、存在的 repo 工作目錄。')
    if not isinstance(agent_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', agent_id):
        raise ConfigError('agent_id 請用穩定名稱，例如 agent-example，不可包含路徑。')
    target = output_directory(Path(output))
    if root not in target.parents:
        raise ConfigError('輸出必須位於目前 repo 內的 Agent 專用子目錄；不可使用跨 repo 的全域目錄。')
    return {'repo_root': str(root), 'agent_id': agent_id}


def check_output_scope(path, scope):
    for name in ('setup.json', 'inventory.json', 'inventory.partial.json'):
        previous = path / name
        if previous.exists():
            try:
                old = json.loads(previous.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                raise ConfigError('已有無法辨識的 repo 盤點資料；請另選此 repo 的 Agent 目錄。') from None
            if not isinstance(old, dict) or old.get('scope') != scope:
                raise ConfigError('目錄已有其他 repo／Agent 或未綁定範圍的舊資料；請在目前 repo 另選目錄重新 setup，不自動搬移或混用。')


def source_info(es, patterns):
    # No API key, Authorization header, env file contents or credential fingerprint.
    return {'transport': 'direct-es-api', 'es_url': es.url.geturl().rstrip('/'),
        'index_patterns': patterns}


def check_output_source(path, source):
    for name in ('inventory.json', 'inventory.partial.json'):
        previous = path / name
        if not previous.exists():
            continue
        try:
            old = json.loads(previous.read_text(encoding='utf-8'))
        except (ValueError, OSError):
            raise ConfigError('輸出目錄已有無法辨識的盤點檔；請另選此 Agent 的獨立目錄。') from None
        if not isinstance(old, dict) or old.get('source') != source:
            raise ConfigError('輸出目錄已有其他來源或舊版盤點；請為此 Agent／資料來源另選目錄。')


class RoutedHTTPS(http.client.HTTPSConnection):
    """Connect to an optional IP while validating the original TLS hostname."""
    def __init__(self, host, port, context, connect_ip=None):
        super().__init__(host, port, context=context, timeout=25)
        self.connect_ip = connect_ip

    def connect(self):
        sock = socket.create_connection((self.connect_ip or self.host, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class ES:
    def __init__(self, url, key, ca=None, connect_ip=None, max_requests=1500):
        if not url:
            raise ConfigError('缺少 ES_URL；請提供 ES HTTPS 位址，或先選擇 MCP 連線方式。')
        try:
            self.url = urlsplit(url)
            self.url.port
        except ValueError:
            raise ConfigError('ES_URL 格式或連接埠錯誤；請提供 ES HTTPS 位址。') from None
        if (self.url.scheme != 'https' or not self.url.hostname or
                self.url.username or self.url.password or self.url.query or
                self.url.fragment or self.url.path not in ('', '/')):
            raise ConfigError('ES_URL 必須是 HTTPS 位址，不可包含帳密、查詢參數或路徑。')
        if self.url.hostname.endswith('.invalid'):
            raise ConfigError('ES_URL 仍是範例位址；請改為已授權的 ES 位址。')
        if not key or key.upper().startswith('REPLACE_'):
            raise ConfigError('缺少有效的 ES_API_KEY；請在執行環境配置唯讀金鑰，不要貼到聊天。')
        self.key, self.connect_ip = key, connect_ip
        self.context = ssl.create_default_context(cafile=ca or None)
        self.requests, self.max_requests = 0, max_requests

    def request(self, method, path, body=None):
        # Only scoped metadata and read-only search endpoints are allowed.
        if not ((method == 'GET' and path.startswith('/_resolve/index/')) or
                (method == 'GET' and path.endswith('/_field_caps?fields=*')) or
                (method == 'POST' and path.endswith('/_search?allow_partial_search_results=false'))):
            raise ValueError('Request outside inventory read-only endpoints')
        if self.requests >= self.max_requests:
            raise RuntimeError('request_budget_exhausted')
        self.requests += 1
        conn = RoutedHTTPS(self.url.hostname, self.url.port or 443, self.context, self.connect_ip)
        try:
            payload = json.dumps(body).encode() if body is not None else None
            conn.request(method, path, payload, {
                'Authorization': 'ApiKey ' + self.key,
                'Content-Type': 'application/json', 'Accept-Encoding': 'identity'})
            response = conn.getresponse()
            if response.status != 200:
                raise RuntimeError('elasticsearch_http_' + str(response.status))
            if response.getheader('Content-Encoding', '').strip().lower() not in ('', 'identity'):
                raise RuntimeError('compressed_response_rejected')
            limit = 8 * 1024 * 1024
            data = response.read(limit + 1)
            if len(data) > limit:
                raise RuntimeError('response_exceeds_8_MiB')
            result = json.loads(data)
            if method == 'POST':
                if result.get('timed_out') or result.get('_shards', {}).get('failed', 0):
                    raise RuntimeError('partial_or_timed_out_search')
                if '_shards' not in result:
                    raise RuntimeError('missing_search_completeness_metadata')
            return result
        finally:
            conn.close()


def pick_field(fields, name):
    for candidate in (name, name + '.keyword'):
        types = fields.get(candidate, {})
        if len(types) == 1:
            kind, caps = next(iter(types.items()))
            if kind in ('keyword', 'ip', 'constant_keyword') and caps.get('aggregatable'):
                return candidate
    return None


def search(es, index, aggs, **extra):
    body = {'size': 0, 'timeout': '5s', 'track_total_hits': False, 'aggs': aggs}
    body.update(extra)
    return es.request('POST', '/' + quote(index, safe='') +
        '/_search?allow_partial_search_results=false', body)


def timestamp_aggs(fields):
    types = fields.get('@timestamp', {})
    if len(types) == 1 and next(iter(types)) in ('date', 'date_nanos'):
        return {'first': {'min': {'field': '@timestamp'}},
                'last': {'max': {'field': '@timestamp'}}}
    return {}


def range_values(aggs):
    return {key: aggs.get(key, {}).get('value_as_string') for key in ('first', 'last')}


def scan_index(es, index, page_size=100, max_pages=100):
    fields = es.request('GET', '/' + quote(index, safe='') + '/_field_caps?fields=*')['fields']
    selected = {name: pick_field(fields, name) for name in IDENTITY}
    times = timestamp_aggs(fields)
    aggs = dict(times)
    presence_filters = {name: {'exists': {'field': name}}
        for name in IMPORTANT if name in fields}
    if presence_filters:
        aggs['presence'] = {'filters': {'filters': presence_filters}}
    for name in ('deviceAction', 'name', 'deviceEventClassId'):
        field = pick_field(fields, name)
        if field:
            aggs['values_' + name] = {'terms': {'field': field, 'size': 10}}
    summary = search(es, index, aggs, track_total_hits=True)
    total = summary['hits']['total']
    if total.get('relation') != 'eq':
        raise RuntimeError('inexact_index_document_count')
    a = summary.get('aggregations', {})
    presence = {name: value['doc_count'] for name, value in
        a.get('presence', {}).get('buckets', {}).items()}
    record = {'index': index, 'status': 'complete', 'scanned_at': now(),
        'document_count': total['value'], 'time_field': '@timestamp' if times else None,
        'time_range': range_values(a), 'field_count': len(fields), 'fields': fields,
        'field_presence': presence, 'identity_fields': selected,
        'missing_deviceAddress_documents': total['value'] - presence.get('deviceAddress', 0),
        'value_examples': {name: a['values_' + name] for name in
            ('deviceAction', 'name', 'deviceEventClassId') if 'values_' + name in a},
        'identity_observations': [], 'identity_pages': 0}
    sources = [{name: {'terms': {'field': field, 'missing_bucket': True}}}
               for name, field in selected.items() if field]
    if not sources or not total['value']:
        if total['value'] and not sources:
            record['identity_status'] = 'no_aggregatable_CEF_identity_fields'
            if 'deviceAddress' in fields and not selected['deviceAddress']:
                record['identity_status'] = 'deviceAddress_not_aggregatable'
                record['status'] = 'partial'
        else:
            record['identity_status'] = 'complete'
        return record
    after = None
    try:
        for page in range(max_pages):
            composite = {'size': page_size, 'sources': sources}
            if after is not None:
                composite['after'] = after
            result = search(es, index, {'identities': {'composite': composite, 'aggs': times}})
            groups = result['aggregations']['identities']
            record['identity_pages'] += 1
            for bucket in groups.get('buckets', []):
                record['identity_observations'].append({
                    **{name: bucket['key'].get(name) for name in IDENTITY},
                    'document_count': bucket['doc_count'], 'time_range': range_values(bucket)})
            next_after = groups.get('after_key')
            if not groups.get('buckets') or next_after is None:
                record['identity_status'] = 'complete'
                break
            if next_after == after:
                raise RuntimeError('repeated_composite_cursor')
            after = next_after
        else:
            record['identity_status'] = 'page_limit_reached'
            record['status'] = 'partial'
    except Exception as exc:
        record['identity_status'] = safe_error(exc)
        record['status'] = 'partial'
    if 'deviceAddress' in fields and not selected['deviceAddress']:
        record['identity_status'] = 'deviceAddress_not_aggregatable'
        record['status'] = 'partial'
    return record


def safe_error(exc):
    if isinstance(exc, ConfigError):
        return str(exc)
    if isinstance(exc, ssl.SSLCertVerificationError):
        return 'TLS 驗證失敗；請核對 ES 主機名稱及 --ca／ES_CA_CERT，不要停用驗證。'
    if isinstance(exc, FileNotFoundError):
        return '指定的設定檔、CA 或路徑不存在；請核對已授權的檔案位置。'
    if isinstance(exc, PermissionError):
        return '無法讀寫指定檔案；請確認設定／CA 可讀，且此 Agent 的輸出目錄可寫。'
    if isinstance(exc, RuntimeError):
        if str(exc) == 'elasticsearch_http_401':
            return 'ES 認證失敗（401）；請核對唯讀金鑰是否正確或已到期。'
        if str(exc) == 'elasticsearch_http_403':
            return 'ES 權限不足（403）；請核對授權索引的 read、view_index_metadata 權限。'
        code = str(exc)
        allowed = {'request_budget_exhausted', 'compressed_response_rejected',
            'response_exceeds_8_MiB', 'partial_or_timed_out_search',
            'missing_search_completeness_metadata', 'inexact_index_document_count',
            'repeated_composite_cursor'}
        if code in allowed or re.fullmatch(r'elasticsearch_http_[0-9]{3}', code):
            return code
        mcp_code = code.split('；', 1)[0]
        mcp_allowed = {'mcp_tool_failed', 'mcp_result_format_unsupported',
            'mcp_request_budget_exhausted', 'mcp_compressed_response_rejected',
            'mcp_response_too_large', 'mcp_connection_failed', 'mcp_rpc_failed',
            'mcp_stream_ended_without_response', 'mcp_tool_list_incomplete',
            'mcp_tool_outside_readonly_tools', 'mcp_missing_list_indices',
            'mcp_index_list_format_unsupported', 'mcp_search_schema_unsupported',
            'mcp_search_incomplete_or_missing_metadata', 'mcp_search_missing_count_metadata',
            'mcp_missing_get_mapping', 'no_known_indexed_cef_fields'}
        if mcp_code in mcp_allowed or re.fullmatch(r'mcp_http_[0-9]{3}', mcp_code):
            return mcp_code
        return 'operation_failed'
    if isinstance(exc, (TimeoutError, ConnectionError, socket.gaierror)):
        return '無法連線 ES；請核對位址、網路與防火牆。'
    # Never include HTTP bodies, headers, raw events or credentials in reports.
    return type(exc).__name__


def merge_devices(records):
    devices = {}
    for record in records:
        for observation in record.get('identity_observations', []):
            address = observation.get('deviceAddress')
            if address is None:
                continue
            device = devices.setdefault(address, {'deviceAddress': address,
                'deviceVendor': set(), 'deviceProduct': set(), 'deviceHostName': set(),
                'indices': set(), 'first': None, 'last': None})
            device['indices'].add(record['index'])
            for field in IDENTITY[1:]:
                if observation.get(field) is not None:
                    device[field].add(observation[field])
            for bound in ('first', 'last'):
                value = observation.get('time_range', {}).get(bound)
                previous = device[bound]
                if value and (not previous or (value < previous if bound == 'first' else value > previous)):
                    device[bound] = value
    return [{k: sorted(v) if isinstance(v, set) else v for k, v in device.items()}
            for _, device in sorted(devices.items())]


def cell(value):
    return str(value if value is not None else '未取得').replace('|', '\\|').replace('\n', ' ')


def markdown(report):
    if report.get('source', {}).get('transport') == 'mcp':
        return mcp_markdown(report)
    lines = ['# ES 基本資料目錄', '', '產生時間：' + report['finished_at'], '',
        '- Repo／Agent：' + cell(report.get('scope', {}).get('repo_root')) + ' / ' + cell(report.get('scope', {}).get('agent_id')),
        '- ES 來源：`' + cell(report.get('source', {}).get('es_url', '未記錄，請重新盤點')) + '`。',
        '- 範圍：`' + ', '.join(report['patterns']) + '`，僅此唯讀金鑰可見的普通索引。',
        '- 狀態：' + report['status'] + '；成功/部分索引 ' + str(len(report['indices'])) +
            '，失敗 ' + str(len(report['errors'])) + '。',
        '- 以 `deviceAddress` 觀察到 ' + str(len(report['devices'])) +
            ' 個不同位址；不代表相同數量的實體設備，也不是全部現役資產清單。',
        '- 無時間篩選，涵蓋目前可見的保留資料；逐索引分頁讀取，不是同一時間快照。',
        '- 沒有可查 deviceAddress 的紀錄不拿 agentAddress、來源或目的 IP 代替；未索引不等於原文沒有該欄位。',
        '- 時間依 @timestamp；其原始 CEF 時間對應仍須查來源解析。',
        '- 設備＋廠商＋產品＋名稱的組合採 composite 分頁；事件/動作範例只列前10值，誤差與截斷見 JSON。',
        '- 本目錄不含原始日誌、金鑰、規則、排程、通知或叢集管理資訊。', '',
        '## 資料來源（包含沒有設備位址的資料）', '',
        '| 索引家族 | 觀察到的廠商／產品 | 索引數 | 有可查deviceAddress的日誌 | 無可查deviceAddress的日誌 |',
        '| --- | --- | --- | --- | --- |']
    families = {}
    for r in report['indices']:
        family = re.sub(r'-\d{8}$', '-*', r['index'])
        item = families.setdefault(family, {'products': set(), 'indices': 0, 'with': 0, 'without': 0})
        item['indices'] += 1
        item['with'] += r['field_presence'].get('deviceAddress', 0)
        item['without'] += r['missing_deviceAddress_documents']
        for observation in r.get('identity_observations', []):
            values = [observation.get('deviceVendor'), observation.get('deviceProduct')]
            if any(values):
                item['products'].add(' / '.join(str(v) for v in values if v))
    for family, item in sorted(families.items()):
        lines.append('| ' + ' | '.join(cell(v) for v in [family,
            ', '.join(sorted(item['products'])) or '未取得可查 CEF 廠商／產品',
            item['indices'], item['with'], item['without']]) + ' |')
    lines += ['', '沒有可查 deviceAddress 不代表沒有日誌；廠商／產品只代表此資料來源，不用來冒充設備位址。', '',
        '## 設備位址與資料位置', '',
        '| deviceAddress | 廠商 | 產品 | 設備名稱 | 索引數 | 最新資料時間 |',
        '| --- | --- | --- | --- | --- | --- |']
    for d in report['devices']:
        lines.append('| ' + ' | '.join(cell(v) for v in [d['deviceAddress'],
            ', '.join(d['deviceVendor']), ', '.join(d['deviceProduct']),
            ', '.join(d['deviceHostName']), len(d['indices']), d['last']]) + ' |')
    lines += ['', '完整設備到索引對照與欄位資訊見同目錄 inventory.json。', '', '## 索引', '',
        '| 索引 | 日誌筆數 | 無可查deviceAddress | 欄位數 | 最早時間 | 最新時間 | 狀態 |',
        '| --- | --- | --- | --- | --- | --- | --- |']
    for r in report['indices']:
        lines.append('| ' + ' | '.join(cell(v) for v in [r['index'], r['document_count'],
            r['missing_deviceAddress_documents'], r['field_count'], r['time_range']['first'],
            r['time_range']['last'], r['status']]) + ' |')
    if report['errors']:
        lines += ['', '## 未完成的索引', '']
        lines += ['- ' + e['index'] + '：' + e['error'] for e in report['errors']]
    return '\n'.join(lines) + '\n'


def mcp_markdown(report):
    source = report['source']
    lines = ['# ES 基本資料目錄（MCP）', '',
        '產生時間：' + report['finished_at'], '',
        '- Repo／Agent：' + cell(report.get('scope', {}).get('repo_root')) + ' / ' + cell(report.get('scope', {}).get('agent_id')),
        '- 來源：' + cell(source['connection_ref']) + '；' + cell(source.get('mcp_url', 'Agent 已連接的原生 MCP')),
        '- 索引範圍：' + cell(', '.join(report['patterns'])) + '，僅 MCP 目前授權可見名稱。',
        '- 狀態：partial；索引／欄位已盤點，設備為查詢視窗內的樣本及前幾名觀察值。',
        '- 查詢可用：' + str(report.get('query_ready', False)) + '；查詢失敗不當成零筆。',
        '- 觀察到 ' + str(len(report['devices'])) + ' 個不同 deviceAddress；不是全部設備數。',
        '- 未取得全保留期文件數、完整設備分頁、精確欄位有值筆數及全保留期時間範圍。',
        '- 無法列出的設備與欄位值為未知，不推論不存在；不要求 ES API Key。',
        '- 時間視窗見各索引；零個觀察值不代表沒有設備，也不代表沒有歷史資料。', '',
        '- 視窗計數的 gte 表示「至少」，不是精確總數。', '',
        '## 索引與欄位', '',
        '| 索引 | 欄位數 | 查詢開始 | 查詢結束 | 視窗文件數／關係 | 設備觀察狀態 |',
        '| --- | --- | --- | --- | --- | --- |']
    for r in report['indices']:
        count = r.get('window_document_count') or {}
        lines.append('| ' + ' | '.join(cell(v) for v in [r['index'], r['field_count'],
            r['query_window']['start'], r['query_window']['end'],
            str(count.get('value', '未知')) + ' / ' + count.get('relation', '未知'), r['identity_status']]) + ' |')
    lines += ['', '## 已觀察的設備位址', '',
        '| deviceAddress | 廠商 | 產品 | 設備名稱 | 索引數 |', '| --- | --- | --- | --- | --- |']
    for d in report['devices']:
        lines.append('| ' + ' | '.join(cell(v) for v in [d['deviceAddress'],
            ', '.join(d['deviceVendor']) or '未知', ', '.join(d['deviceProduct']) or '未知',
            ', '.join(d['deviceHostName']) or '未知', len(d['indices'])]) + ' |')
    lines += ['', '完整欄位型別、樣本有值證據、統計截斷資訊見同目錄 inventory.json。']
    if report['not_scanned_indices']:
        lines += ['', '尚未盤點的索引：' + str(len(report['not_scanned_indices']))]
    if report['errors']:
        lines += ['', '## 未完成項目', '']
        lines += ['- ' + cell(e['index']) + '：' + cell(e['error']) for e in report['errors']]
    return '\n'.join(lines) + '\n'


def atomic_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                prefix='.inventory-', delete=False) as f:
            name = f.name
            f.write(text)
        os.replace(name, path)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


def publish_report(path, report):
    stem = 'inventory'
    previous = path / 'inventory.json'
    if report['status'] != 'complete' and previous.exists():
        old = json.loads(previous.read_text(encoding='utf-8'))
        if old.get('status') == 'complete':
            stem = 'inventory.partial'
    atomic_write(path / (stem + '.json'), json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    atomic_write(path / (stem + '.md'), markdown(report))
    return stem


def scan(es, patterns, scope, max_indices=None, page_size=100, max_pages=100):
    source = source_info(es, patterns)
    resolved = es.request('GET', '/_resolve/index/' + quote(','.join(patterns), safe='*,-_.') + '?expand_wildcards=open')
    names = sorted({x['name'] for x in resolved.get('indices', [])
        if not x['name'].startswith('.') and any(fnmatch.fnmatchcase(x['name'], p) for p in patterns)})
    report = {'schema_version': 2, 'source': source,
        'configuration': 'explicit-env-file',
        'started_at': now(), 'finished_at': None,
        'patterns': patterns, 'status': 'running', 'resolved_index_count': len(names),
        'not_scanned_indices': names[max_indices:] if max_indices else [],
        'excluded_aliases': [x['name'] for x in resolved.get('aliases', [])],
        'excluded_data_streams': [x['name'] for x in resolved.get('data_streams', [])],
        'indices': [], 'devices': [], 'errors': [], 'http_requests': 0}
    if scope is not None:
        report['scope'] = scope
    targets = names[:max_indices] if max_indices else names
    for i, index in enumerate(targets, 1):
        try:
            record = scan_index(es, index, page_size, max_pages)
            report['indices'].append(record)
            print(str(i) + '/' + str(len(targets)) + ' ' + index + ' ' + record['status'], flush=True)
        except Exception as exc:
            report['errors'].append({'index': index, 'error': safe_error(exc)})
            print(str(i) + '/' + str(len(targets)) + ' ' + index + ' failed: ' + safe_error(exc), flush=True)
        if es.requests >= es.max_requests:
            report['not_scanned_indices'].extend(targets[i:])
            break
        time.sleep(0.1)
    report['finished_at'], report['http_requests'] = now(), es.requests
    report['devices'] = merge_devices(report['indices'])
    incomplete = (not names or report['errors'] or report['not_scanned_indices'] or
        report['excluded_aliases'] or report['excluded_data_streams'] or
        any(r['status'] != 'complete' for r in report['indices']))
    report['status'] = 'partial' if incomplete else 'complete'
    return report


if __name__ == '__main__':
    print('請使用 es.py setup；此模組不提供獨立執行入口。', flush=True)
    raise SystemExit(1)
