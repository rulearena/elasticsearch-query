# 初始化與連線設定

首次使用、來源改變或要求重新設定時，Agent 執行本流程。先沿用已知設定，只問無法從工作區與既有工具確定的資訊，不把整張設定表丟給使用者。

## 保存位置

每個使用者 repo、Agent 和來源各有自己的目錄：

```text
<repo>/.local/elasticsearch-query/<agent_id>/<source_id>/profile.json
```

`repo_root` 使用絕對路徑。以下 profile 都放在該資料目錄，`output_dir: "."` 表示 profile 所在目錄。所有相對檔案路徑都以 profile 所在目錄解析。Agent 確認此目錄被 Git 忽略；憑證只保存變數名稱或已授權設定檔位置。

## Agent 已連接的 MCP（遠端或本機 stdio）

沿用現有工具，不再索取 MCP Token 或 ES API Key。profile 格式如下，佔位值由 Agent 換成本次實際資料：

```json
{
  "mode": "mcp-native",
  "repo_root": "/path/to/current-repo",
  "agent_id": "agent-example",
  "connection_ref": "mcp-example",
  "output_dir": ".",
  "index_patterns": ["*"],
  "lookback_hours": 24
}
```

`*` 僅篩選 MCP 已授權列出的索引名稱。實際可見範圍由 server 限制。

Agent 先讀工具 schema，再列索引、讀 field capabilities 並做少量、明確時間與欄位的查詢。把當次實際回應整理成 capture；不可捏造資料或要求使用者手寫工具回應。此 adapter 支援 `list_indices`、`get_mapping`、`search_events` 三種邏輯工具。其他 schema 需依實際工具契約轉換；無法相容時說明缺少的能力，不要求 ES Key。

capture 結構如下，僅示範格式，不能當成實際結果：

```json
{
  "connection_ref": "mcp-example",
  "tools": [
    {"name": "list_indices", "inputSchema": {"type": "object"}},
    {"name": "get_mapping", "inputSchema": {"type": "object"}},
    {"name": "search_events", "inputSchema": {"type": "object"}}
  ],
  "indices_result": ["security-events-example"],
  "records": [{
    "index": "security-events-example",
    "start": "2026-11-01T00:00:00Z",
    "end": "2026-11-02T00:00:00Z",
    "mapping_result": {"fields": {}},
    "search_result": {
      "timed_out": false,
      "shards": {"failed": 0},
      "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}
    }
  }]
}
```

```sh
python3 "$SKILL_DIR/scripts/es.py" setup --profile "$OUTPUT_DIR/profile.json" --capture "$OUTPUT_DIR/capture.json"
```

Capture 放在同一 repo 的私有資料目錄，只取必要資料，產生報告並核對後刪除短期 capture。後續原生 MCP 查詢由 Agent 直接呼叫現有工具，不由腳本重新啟動 MCP。

## 獨立 HTTP MCP

遠端使用 HTTPS；只有回環位址可以使用不帶 Token 的 HTTP。虛構的 `.invalid` 位址必須換成已授權 endpoint：

```json
{
  "mode": "mcp-http",
  "repo_root": "/path/to/current-repo",
  "agent_id": "agent-example",
  "connection_ref": "mcp-example",
  "output_dir": ".",
  "url": "https://mcp.example.invalid/mcp",
  "auth": "bearer",
  "token_env": "ES_MCP_TOKEN",
  "index_patterns": ["security-events-*"]
}
```

Token 由指定的執行環境變數提供，不寫進 profile 或網址。本機無認證服務明確設 `auth: none`。OAuth 或不相容 transport 沿用 Agent 原生 MCP，不改向使用者索取 ES API Key。

## 直接 ES API

profile 只參照已授權的連線設定。設定格式見 [inventory.env.example](../scripts/inventory.env.example)；真實設定檔放在 skill 外的安全位置，不存進 Git。

```json
{
  "mode": "es-api",
  "repo_root": "/path/to/current-repo",
  "agent_id": "agent-example",
  "connection_ref": "es-api-example",
  "output_dir": ".",
  "env_file": "/path/to/authorized/inventory.env",
  "index_patterns": ["security-events-*"]
}
```

HTTP MCP 和直接 API 共用命令：

```sh
python3 "$SKILL_DIR/scripts/es.py" setup --profile "$OUTPUT_DIR/profile.json"
```

setup 會實際執行唯讀盤點並保存 `setup.json` 及報告。`ready_with_limits` 表示查詢可用但盤點有缺漏；`needs_attention` 表示查詢尚未驗證。`inventory.partial.json` 保留最新部分結果，舊完整報告不被覆蓋。設備觀察、mapping、樣本都不能當成完整資產清冊。

同一 Agent／來源的初始化或查詢執行中時，程式會拒絕第二個同時寫入的操作；完成或程序結束後鎖自動釋放。其他 Agent／來源仍各自執行。

回報連線方式、實際測過的範圍、報告位置與缺漏。已有使用者問題就繼續查詢。排程狀態未核對保持未知，不因初始化成功建立排程。
