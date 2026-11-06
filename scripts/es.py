#!/usr/bin/env python3
"""One entry point for setup, scoped inventory reading and read-only queries."""
import argparse
from contextlib import contextmanager
import fnmatch
import os
import re
import stat
import uuid
import json
from pathlib import Path

import inventory_es as direct
import mcp_inventory as mcp

MODES = ('mcp-native', 'mcp-http', 'es-api')


class SourceConflict(direct.ConfigError):
    pass


def validate(profile, base):
    allowed = {'mode', 'connection_ref', 'output_dir', 'index_patterns', 'url',
        'token_env', 'env_file', 'ca_file', 'auth', 'lookback_hours', 'start', 'end',
        'max_indices', 'max_requests', 'connect_ip', 'timezone', 'index_date_timezone',
        'repo_root', 'agent_id'}
    if not isinstance(profile, dict) or set(profile) - allowed:
        raise direct.ConfigError('profile 含未知欄位；不要填入 Token／API Key 本身，只保存設定位置或環境變數名稱。')
    missing = [n for n in ('mode', 'connection_ref', 'output_dir', 'repo_root', 'agent_id') if not profile.get(n)]
    if missing:
        raise direct.ConfigError('尚缺：' + '、'.join(missing) + '。請只補這些資料。')
    result = dict(profile)
    if result['mode'] not in MODES:
        raise direct.ConfigError('mode 請選 mcp-native、mcp-http 或 es-api。')
    if result.get('index_date_timezone') not in (None, 'UTC'):
        raise direct.ConfigError('index_date_timezone 目前只接受已確認的 UTC 日索引慣例；未確認時省略。')
    if not isinstance(result['connection_ref'], str) or not result['connection_ref'].strip():
        raise direct.ConfigError('connection_ref 需為此 Agent 所選連線的名稱。')
    for name in ('output_dir', 'env_file', 'ca_file', 'repo_root'):
        if result.get(name):
            path = Path(result[name]).expanduser()
            result[name] = str((path if path.is_absolute() else base / path).resolve())
    output = direct.output_directory(Path(result['output_dir']))
    result['output_dir'] = str(output)
    scope = direct.execution_scope(result['repo_root'], result['agent_id'], output)
    direct.check_output_scope(output, scope)
    if result['mode'] == 'mcp-http' and not result.get('url'):
        raise direct.ConfigError('尚缺 MCP url；已有原生 MCP 連線時可選 mcp-native，無須重新提供 Token。')
    if result['mode'] == 'es-api' and not result.get('env_file'):
        raise direct.ConfigError('直接 ES API 模式需提供 env_file 位置；MCP 使用者不需此設定。')
    result.setdefault('index_patterns', ['*'])
    if not isinstance(result['index_patterns'], list) or not result['index_patterns'] or not all(
            isinstance(p, str) and p for p in result['index_patterns']):
        raise direct.ConfigError('index_patterns 需為索引名稱／樣板的非空清單。')
    if result.get('auth', 'bearer') not in ('bearer', 'none'):
        raise direct.ConfigError('HTTP helper 支援 bearer／none；其他認證請使用已配置的 mcp-native 連線。')
    token_env = result.get('token_env', 'MCP_TOKEN')
    mcp.validate_token_name(token_env)
    for name, maximum in (('max_indices', 10000), ('max_requests', 10000), ('lookback_hours', 24)):
        if name in result and (type(result[name]) is not int or not 1 <= result[name] <= maximum):
            raise direct.ConfigError(name + ' 需為正整數，且不超過 ' + str(maximum) + '。')
    if result['mode'] != 'es-api':
        mcp.window(result)
    if result.get('url'):
        from urllib.parse import urlsplit
        url = urlsplit(result['url'])
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise direct.ConfigError('profile 的 MCP url 不可內含帳密、Token、查詢參數或片段。')
        if url.hostname.endswith('.invalid'):
            raise direct.ConfigError('MCP url 仍是範例位址；請使用已授權的 MCP endpoint。')
        if result['mode'] == 'mcp-http':
            mcp.validate_endpoint_security(url.geturl(), result.get('auth', 'bearer') == 'bearer')
    return result


@contextmanager
def output_lock(profile):
    folder = Path(profile['output_dir'])
    scope = direct.execution_scope(profile['repo_root'], profile['agent_id'], folder)
    direct.check_output_scope(folder, scope)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(str(folder / '.write.lock'), flags, 0o600)
    locked = False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise direct.ConfigError('Agent 操作鎖不是一般檔案，請核對輸出目錄。')
        try:
            if os.name == 'nt':
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b'0')
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError:
            raise direct.ConfigError('同一 Agent／來源已有操作執行中，請完成後再重試。') from None
        yield
    finally:
        if locked:
            if os.name == 'nt':
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def mcp_source(profile):
    source = {'transport': 'mcp', 'connection_ref': profile['connection_ref'],
        'index_patterns': profile['index_patterns']}
    if profile.get('url'):
        source['mcp_url'] = profile['url']
    return source


def direct_client(profile, max_requests):
    config = direct.load_env(Path(profile['env_file']))
    patterns = [p.strip() for p in config.get('ES_INDEX_PATTERNS', '').split(',') if p.strip()]
    if not patterns or any(not re.fullmatch(r'[a-z0-9_.*-]+', p) or p in ('*', '_all') or p.startswith('.') for p in patterns):
        raise direct.ConfigError('設定檔需有明確授權的 ES_INDEX_PATTERNS。')
    if profile['index_patterns'] != ['*'] and set(profile['index_patterns']) != set(patterns):
        raise SourceConflict('profile 與設定檔的索引範圍不同；尚未連線。')
    client = direct.ES(config.get('ES_URL', ''), config.get('ES_API_KEY', ''),
        profile.get('ca_file') or config.get('ES_CA_CERT'), profile.get('connect_ip'), max_requests)
    return client, patterns


def check_source(output, source, previous):
    if previous.get('schema_version') == 3 and previous.get('source') is not None and previous['source'] != source:
        raise direct.ConfigError('設定來源與 setup 綁定不同；請另選來源目錄。')
    direct.check_output_source(output, source)


def attempt_error(exc):
    if isinstance(exc, direct.ConfigError):
        return {'class': 'configuration', 'code': 'configuration_failed'}
    if isinstance(exc, mcp.MCPError):
        return {'class': 'mcp', 'code': 'mcp_failed'}
    if isinstance(exc, OSError):
        return {'class': 'io', 'code': 'io_failed'}
    return {'class': 'operation', 'code': 'operation_failed'}


def execute(profile, capture=None):
    if profile['mode'] == 'mcp-native' and capture is None:
        raise direct.ConfigError('請由 Agent 使用已連接的原生 MCP 工具取得 capture；不需 ES Key。')
    with output_lock(profile):
        output = Path(profile['output_dir'])
        scope = direct.execution_scope(profile['repo_root'], profile['agent_id'], output)
        direct.check_output_scope(output, scope)
        previous_file = output / 'setup.json'
        previous = json.loads(previous_file.read_text(encoding='utf-8')) if previous_file.exists() else {}
        trusted = previous if previous.get('schema_version') == 3 else {}
        status = {'schema_version': 3, 'scope': scope, 'source': trusted.get('source'),
            'profile': trusted.get('profile', profile), 'verified_at': trusted.get('verified_at'),
            'query_ready': False, 'inventory_status': previous.get('inventory_status'),
            'inventory_report_stem': previous.get('inventory_report_stem'),
            'setup_status': 'needs_attention', 'last_success': trusted.get('last_success'),
            'periodic_refresh': previous.get('periodic_refresh', 'unknown'),
            'last_attempt': {'status': 'running', 'started_at': direct.now(), 'finished_at': None}}

        def save_failed(exc):
            status['last_attempt'].update(status='failed', finished_at=direct.now(), error=attempt_error(exc))
            status['source'] = trusted.get('source')
            status['last_success'] = trusted.get('last_success')
            status['verified_at'] = trusted.get('verified_at')
            status['profile'] = trusted.get('profile', profile)
            status['query_ready'] = False
            status['setup_status'] = 'needs_attention'
            direct.atomic_write(previous_file, json.dumps(status, ensure_ascii=False, indent=2) + '\n')

        if profile['mode'] == 'es-api':
            try:
                client, patterns = direct_client(profile, profile.get('max_requests', 1500))
            except SourceConflict:
                raise
            except (OSError, ValueError, RuntimeError) as exc:
                save_failed(exc)
                raise
            source = direct.source_info(client, patterns)
        else:
            source = mcp_source(profile)
        check_source(output, source, previous)
        try:
            direct.atomic_write(previous_file, json.dumps(status, ensure_ascii=False, indent=2) + '\n')
            if profile['mode'] == 'es-api':
                report = direct.scan(client, patterns, scope, profile.get('max_indices'))
                ready = bool(report['indices']) and not report['errors']
            elif profile['mode'] == 'mcp-native':
                report = mcp.from_capture(profile, capture)
                ready = report['query_ready']
            else:
                report = mcp.scan_client(mcp.http_client(profile), profile)
                ready = report['query_ready']
            if report.get('scope') != scope or report.get('source') != source:
                raise direct.ConfigError('盤點結果與本次範圍或來源不同。')
            stem = direct.publish_report(output, report)
            status.update(source=source, profile={**profile, 'index_patterns': report['patterns']},
                query_ready=ready, inventory_status=report['status'], inventory_report_stem=stem,
                setup_status=('ready' if report['status'] == 'complete' else 'ready_with_limits') if ready else 'needs_attention')
            status['last_attempt'].update(status='completed', finished_at=direct.now())
            if ready:
                status['verified_at'] = status['last_attempt']['finished_at']
                status['last_success'] = {'verified_at': status['verified_at'],
                    'inventory_status': report['status'], 'index_count': len(report['indices'])}
            direct.atomic_write(previous_file, json.dumps(status, ensure_ascii=False, indent=2) + '\n')
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError, direct.http.client.HTTPException) as exc:
            save_failed(exc)
            raise
        return status


def project(report, device=None, index=None, field=None):
    result = {key: report.get(key) for key in
        ('schema_version', 'scope', 'source', 'status', 'started_at', 'finished_at',
         'setup_status', 'query_ready', 'last_attempt', 'last_success')}
    if device is not None:
        result['devices'] = [d for d in report.get('devices', []) if d.get('deviceAddress') == device]
    elif index is not None:
        matches = [r for r in report.get('indices', []) if r.get('index') == index]
        if field is not None:
            result['indices'] = [{'index': r['index'], 'status': r.get('status'),
                'field': field, 'capabilities': r.get('fields', {}).get(field),
                'indexed_documents': r.get('field_presence', {}).get(field)} for r in matches]
        else:
            result['indices'] = [{k: v for k, v in r.items()
                if k not in ('fields', 'identity_observations')} for r in matches]
        result['errors'] = [e for e in report.get('errors', []) if e.get('index') == index]
    else:
        result.update(index_count=len(report.get('indices', [])),
            deviceAddress_count=len(report.get('devices', [])),
            error_count=len(report.get('errors', [])))
    return result


def load_latest(input_dir, repo_root, agent_id):
    root = repo_root.expanduser().resolve()
    folder = input_dir.expanduser().resolve()
    if not root.is_dir() or root not in folder.parents:
        raise ValueError('輸出目錄必須位於指定 repo 內。')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', agent_id):
        raise ValueError('agent_id 格式錯誤。')
    skill_root = Path(__file__).resolve().parents[1]
    if folder == skill_root or skill_root in folder.parents:
        raise ValueError('不可從共用 skill 目錄讀取執行資料。')
    expected_scope = {'repo_root': str(root), 'agent_id': agent_id}
    setup = json.loads((folder / 'setup.json').read_text(encoding='utf-8'))
    if not isinstance(setup, dict) or setup.get('scope') != expected_scope:
        raise ValueError('setup 紀錄不屬於指定的 repo／Agent。')
    if setup.get('schema_version') != 3 or not isinstance(setup.get('source'), dict) or not setup['source']:
        raise ValueError('setup 缺少獨立來源綁定；請重新 setup。')
    stem = setup.get('inventory_report_stem')
    if stem not in ('inventory', 'inventory.partial'):
        raise ValueError('setup 沒有指向可讀取的最新盤點。')
    report = json.loads((folder / (stem + '.json')).read_text(encoding='utf-8'))
    if not isinstance(report, dict) or report.get('scope') != expected_scope:
        raise ValueError('盤點報告不屬於指定的 repo／Agent。')
    if report.get('source') != setup['source']:
        raise ValueError('盤點來源與 setup 綁定不同；請核對來源目錄。')
    return {**report, **{key: setup.get(key) for key in
        ('setup_status', 'query_ready', 'last_attempt', 'last_success')}}


def field_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z_@][A-Za-z0-9_.@-]{0,127}', value):
        raise direct.ConfigError('欄位需為明確名稱，不使用萬用字元或表示式。')
    return value


def validate_clause(clause, depth=0):
    if depth > 10 or not isinstance(clause, dict) or len(clause) != 1:
        raise direct.ConfigError('Query DSL 結構無效或過深。')
    op, value = next(iter(clause.items()))
    if op == 'match_all' and value == {}:
        return set()
    if op == 'bool' and isinstance(value, dict) and value and not set(value) - {'must', 'filter', 'must_not', 'should', 'minimum_should_match'}:
        fields = set()
        for key, items in value.items():
            if key == 'minimum_should_match':
                if type(items) is not int or not 0 <= items <= 100:
                    raise direct.ConfigError('minimum_should_match 需為 0–100 整數。')
                continue
            items = items if isinstance(items, list) else [items]
            if not 1 <= len(items) <= 100:
                raise direct.ConfigError('bool 條件數需為 1–100。')
            for item in items:
                fields.update(validate_clause(item, depth + 1))
        return fields
    if op == 'exists' and isinstance(value, dict) and set(value) == {'field'}:
        return {field_name(value['field'])}
    if op in ('term', 'terms', 'match', 'match_phrase', 'range') and isinstance(value, dict) and len(value) == 1:
        field, condition = next(iter(value.items()))
        field_name(field)
        scalar = lambda x: isinstance(x, (str, int, float, bool)) and x is not None
        valid = scalar(condition) if op in ('term', 'match', 'match_phrase') else False
        if op == 'terms':
            valid = isinstance(condition, list) and 1 <= len(condition) <= 100 and all(scalar(x) for x in condition)
        if op == 'range':
            valid = isinstance(condition, dict) and bool(condition) and not set(condition) - {'gt', 'gte', 'lt', 'lte', 'format', 'time_zone'} and any(k in condition for k in ('gt', 'gte', 'lt', 'lte')) and all(scalar(x) for x in condition.values())
        if valid:
            return {field}
    raise direct.ConfigError('此查詢器支援 bool、term、terms、match、match_phrase、range、exists、match_all；不執行 scripts 或任意 API。')


def query_request(value):
    allowed = {'index', 'start', 'end', 'time_field', 'fields', 'limit', 'filters', 'query', 'aggregate_field'}
    if not isinstance(value, dict) or set(value) - allowed or not all(n in value for n in ('index', 'start', 'end', 'fields')):
        raise direct.ConfigError('查詢需有 index、start、end、fields，只接受已支援的查詢欄位。')
    request = dict(value)
    if not isinstance(request['index'], str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,254}', request['index']):
        raise direct.ConfigError('index 需為一個明確的普通索引名稱。')
    if not all(isinstance(request[name], str) for name in ('start', 'end')):
        raise direct.ConfigError('start、end 需為含時區的 ISO 時間字串。')
    request['start'], request['end'] = mcp.window(request)
    request['time_field'] = field_name(request.get('time_field', '@timestamp'))
    fields = request['fields']
    if not isinstance(fields, list) or not 1 <= len(fields) <= 30:
        raise direct.ConfigError('fields 需明確列出 1–30 個必要欄位。')
    for name in fields:
        field_name(name)
    request.setdefault('limit', 3)
    if type(request['limit']) is not int or not 1 <= request['limit'] <= 100:
        raise direct.ConfigError('limit 需為 1–100。')
    filters = request.setdefault('filters', {})
    if not isinstance(filters, dict) or len(filters) > 20:
        raise direct.ConfigError('filters 需為最多 20 個精確條件。')
    for key, item in filters.items():
        validate_clause({'term': {key: item}})
    if 'query' in request:
        validate_clause(request['query'])
    if 'aggregate_field' in request:
        field_name(request['aggregate_field'])
    return request


def source_value(source, name):
    if name in source:
        return source[name]
    value = source
    for part in name.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def query_result(result, request):
    shards = result.get('_shards', result.get('shards'))
    total = result.get('hits', {}).get('total')
    if result.get('timed_out') is not False or not isinstance(shards, dict) or shards.get('failed') != 0:
        raise direct.ConfigError('查詢逾時、分片失敗或缺少完整性資訊；不能當成零筆。')
    if not isinstance(total, dict) or total.get('relation') not in ('eq', 'gte') or type(total.get('value')) is not int or total['value'] < 0:
        raise direct.ConfigError('查詢缺少可判讀的計數資訊。')
    hits = result.get('hits', {}).get('hits', [])
    if not isinstance(hits, list):
        raise direct.ConfigError('查詢樣本格式錯誤。')
    samples = [{name: source_value(hit.get('_source', {}), name) for name in request['fields']}
        for hit in hits[:request['limit']]]
    output = {'total': total, 'samples': samples, 'sample_limit': request['limit'],
        'status': 'complete' if total['relation'] == 'eq' else 'partial'}
    if 'aggregate_field' in request:
        top = result.get('aggregations', {}).get('top_values')
        if not isinstance(top, dict) or not isinstance(top.get('buckets'), list):
            raise direct.ConfigError('查詢缺少要求的統計結果。')
        output['top_values'] = {k: top.get(k) for k in ('sum_other_doc_count', 'doc_count_error_upper_bound')}
        output['top_values']['buckets'] = [{k: b.get(k) for k in ('key', 'doc_count')} for b in top['buckets'][:20]]
        if len(top['buckets']) > 20 or top.get('sum_other_doc_count') != 0 or top.get('doc_count_error_upper_bound') != 0:
            output['status'] = 'partial'
    return output


def run_query(profile, value):
    request = query_request(value)
    with output_lock(profile):
        return execute_query(profile, request)


def execute_query(profile, request):
    output = Path(profile['output_dir'])
    scope = direct.execution_scope(profile['repo_root'], profile['agent_id'], output)
    latest = load_latest(output, Path(profile['repo_root']), profile['agent_id'])
    if profile['mode'] == 'mcp-native':
        raise direct.ConfigError('此來源使用 Agent 已連接的原生 MCP；請由 Agent 呼叫工具，不索取 ES API Key。')
    if not any(fnmatch.fnmatchcase(request['index'], p) for p in profile['index_patterns']):
        raise direct.ConfigError('查詢索引超出 profile 範圍。')
    if profile['mode'] == 'es-api':
        client, patterns = direct_client(profile, 3)
        if not any(fnmatch.fnmatchcase(request['index'], p) for p in patterns):
            raise direct.ConfigError('查詢索引超出設定檔範圍。')
        source = direct.source_info(client, patterns)
        if source != latest['source']:
            raise direct.ConfigError('本次來源與 setup 綁定不同；尚未連線。')
        direct.check_output_source(output, source)
        resolved = client.request('GET', '/_resolve/index/' + request['index'] + '?expand_wildcards=open')
        if request['index'] not in {r['name'] for r in resolved.get('indices', [])}:
            raise direct.ConfigError('指定索引不在目前可見的普通索引中。')
        fields = client.request('GET', '/' + request['index'] + '/_field_caps?fields=*').get('fields', {})
        needed = set(request['fields']) | set(request['filters']) | {request['time_field']}
        needed.update(validate_clause(request.get('query', {'match_all': {}})))
        if 'aggregate_field' in request:
            needed.add(request['aggregate_field'])
        if any(name not in fields for name in needed):
            raise direct.ConfigError('查詢含目前未確認的欄位。')
        time_caps = fields[request['time_field']]
        if not time_caps or any(kind not in ('date', 'date_nanos') or not caps.get('searchable') for kind, caps in time_caps.items()):
            raise direct.ConfigError('時間欄位必須是可搜尋的日期欄位。')
        if 'aggregate_field' in request and any(not c.get('aggregatable') for c in fields[request['aggregate_field']].values()):
            raise direct.ConfigError('指定統計欄位不可聚合。')
        conditions = [{'range': {request['time_field']: {'gte': request['start'], 'lt': request['end']}}}]
        conditions.extend({'term': {name: value}} for name, value in request['filters'].items())
        body = {'query': {'bool': {'filter': conditions, 'must': [request.get('query', {'match_all': {}})]}},
            '_source': request['fields'], 'size': request['limit'], 'timeout': '5s', 'track_total_hits': True}
        if 'aggregate_field' in request:
            body['aggs'] = {'top_values': {'terms': {'field': request['aggregate_field'], 'size': 20}}}
        result = client.request('POST', '/' + request['index'] + '/_search?allow_partial_search_results=false', body)
    else:
        if 'query' in request:
            raise direct.ConfigError('HTTP MCP 只用其 search_events 介面；不接收 ES Query DSL。')
        source = mcp_source(profile)
        if source != latest['source']:
            raise direct.ConfigError('本次來源與 setup 綁定不同；尚未連線。')
        direct.check_output_source(output, source)
        client = mcp.http_client(profile)
        selected = mcp.tool_map(client.initialize())
        if 'search_events' not in selected:
            raise direct.ConfigError('此 MCP 沒有支援的 search_events 工具。')
        client.allowed = {v['name'] for v in selected.values()}
        names = mcp.names_from(client.call(selected['list_indices']['name'], {}))
        if request['index'] not in names:
            raise direct.ConfigError('指定索引不在目前 MCP 可見範圍。')
        arguments = mcp.search_arguments(request, selected['search_events'].get('inputSchema', {}))
        result = client.call(selected['search_events']['name'], arguments)
    report = {'schema_version': 1, 'scope': scope, 'source': source, 'queried_at': direct.now(),
        'request': request, 'result': query_result(result, request)}
    evidence = output / 'queries' / (uuid.uuid4().hex + '.json')
    direct.atomic_write(evidence, json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    return {**report, 'evidence_file': str(evidence)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('setup', 'query'):
        sub = commands.add_parser(command)
        sub.add_argument('--profile', type=Path, required=True)
        if command == 'setup':
            sub.add_argument('--capture', type=Path)
        else:
            sub.add_argument('--request', type=Path, required=True)
    sub = commands.add_parser('inventory')
    sub.add_argument('--input-dir', type=Path, required=True)
    sub.add_argument('--repo-root', type=Path, required=True)
    sub.add_argument('--agent-id', required=True)
    group = sub.add_mutually_exclusive_group()
    group.add_argument('--device')
    group.add_argument('--index')
    sub.add_argument('--field')
    args = parser.parse_args()
    if args.command == 'inventory':
        if args.field is not None and args.index is None:
            parser.error('--field requires --index')
        result = project(load_latest(args.input_dir, args.repo_root, args.agent_id), args.device, args.index, args.field)
    else:
        profile = validate(json.loads(args.profile.read_text(encoding='utf-8')), args.profile.resolve().parent)
        repo = Path(profile['repo_root'])
        if repo not in args.profile.resolve().parents:
            raise direct.ConfigError('profile 也必須保存於目前 repo，不使用跨 repo 的全域設定檔。')
        data_file = args.capture if args.command == 'setup' else args.request
        if data_file and repo not in data_file.resolve().parents:
            raise direct.ConfigError('capture／request 必須位於目前 repo。')
        if args.command == 'query':
            result = run_query(profile, json.loads(data_file.read_text(encoding='utf-8')))
        else:
            result = execute(profile, json.loads(data_file.read_text(encoding='utf-8')) if data_file else None)
            print(json.dumps({k: result[k] for k in ('setup_status', 'query_ready', 'inventory_status', 'inventory_report_stem', 'periodic_refresh')}, ensure_ascii=False))
            return 0 if result['query_ready'] else 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError, direct.http.client.HTTPException) as exc:
        print('ES operation stopped: ' + direct.safe_error(exc), flush=True)
        raise SystemExit(1)
