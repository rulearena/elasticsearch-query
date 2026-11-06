# 查詢與盤點讀取

先完成初始化，沿用同一份 profile。Agent 依問題確認時區、時間欄位、授權索引和必要欄位，再執行查詢。不要把範例日期或數字當成結果。

## 原生 MCP

Agent 直接用現有工具查詢，遵守當次 schema。MCP 使用者不額外提供 ES API Key。保留來源、條件、時間、計數單位和完整性；若工具不能分頁或計算全量，就明確回報限制。

## 直接 API／HTTP MCP

Agent 將本次條件保存成目前 repo 內的 `request.json`。以下全部為虛構範例：

```json
{
  "index": "security-events-example",
  "start": "2026-11-01T00:00:00Z",
  "end": "2026-11-02T00:00:00Z",
  "time_field": "@timestamp",
  "fields": ["@timestamp", "deviceAddress", "deviceAction"],
  "limit": 3,
  "filters": {"deviceAction": "deny"}
}
```

```sh
python3 "$SKILL_DIR/scripts/es.py" query --profile "$OUTPUT_DIR/profile.json" --request "$OUTPUT_DIR/request.json"
```

`index` 必須是一個實際可見、符合 profile 範圍的普通索引；不接受萬用字元、alias 或跨索引字串。時間需帶時區，使用 `[start,end)`，單次最多 24 小時；更長範圍拆成不重疊區間。`fields` 必填 1–30 個欄位，`limit` 為 1–100；`filters` 是最多 20 個同時成立的精確條件。

需要單一欄位前幾名時可加 `aggregate_field`。它是最多 20 個 terms 值，不是完整設備清單或 distinct count。保留未顯示 bucket 和誤差資訊。

直接 API 可另外提供 `query`，由 Agent 組合受支援的 Query DSL，例如：

```json
{
  "bool": {
    "should": [
      {"term": {"deviceAction": "deny"}},
      {"term": {"deviceAction": "drop"}}
    ],
    "minimum_should_match": 1
  }
}
```

把此物件放入 request 的 `query`。支援 `bool`、`term`、`terms`、`match`、`match_phrase`、`range`、`exists`、`match_all`；不接收 scripts、寫入 API 或任意 URL。程式另外強制套用 request 的時間範圍、欄位和樣本上限；精確範圍及欄位權限仍由 ES 服務端執行。KQL／Lucene 只有在其他已授權工具明確接受它們時才使用，不能直接貼進這份 Query DSL 物件。

HTTP MCP 依 `search_events` 介面處理 request，不接受 `query` DSL。工具 schema 不支援的條件要回報缺少能力，不自動改走 ES API。

## 證據與結果

成功查詢會回傳結果，並把同一份證據保存在此 repo／Agent／來源目錄的 `queries/`：來源、scope、查詢時間、實際 request、計數、指定欄位樣本及統計限制。不同查詢使用不同檔名，檔案放在 Git 忽略區。原生 MCP 查詢由 Agent 以相同原則保存必要證據。

- `total.relation=eq` 才是精確文件數；`gte` 是至少該數量。
- `complete` 表示當次計數與要求的統計沒有已知截斷，不代表返回全部文件。樣本數仍受 `limit` 限制。
- timeout、分片失敗或缺少完整性狀態會停止，不能當成零筆。
- 文件筆數、CEF `baseEventCount`、不同 IP 數及去重後事件數不同，不互相代替。
- 不同索引、alias、data stream 或收集路徑可能重複，未確認前不直接加總。
- 查不到時核對時間、來源、實際欄位值及權限；調整條件後清楚說明，不偷偷換問題。

## 讀取盤點

```sh
python3 "$SKILL_DIR/scripts/es.py" inventory --input-dir "$OUTPUT_DIR" --repo-root "$REPO_ROOT" --agent-id "$AGENT_ID"
```

可加 `--device 192.0.2.10`，或 `--index security-events-example --field deviceAddress` 只讀必要片段。上述位址與索引為虛構。讀取器驗 scope 並依 setup 指向最新完整或部分報告；遇到新索引、解析變動或過時資料，先更新盤點。
