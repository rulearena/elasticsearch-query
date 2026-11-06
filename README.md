# elasticsearch-query

這個資料夾就是一個 skill，讓 AI 初始化連線、盤點並唯讀查詢 Elasticsearch 資安日誌。支援 Agent 既有／本機 MCP、HTTP MCP 和直接 ES API。

- 技能入口：[SKILL.md](SKILL.md)。
- 操作入口：[scripts/es.py](scripts/es.py)：`setup` 初始化／更新、`query` 查詢、`inventory` 查看盤點。
- 使用說明：[連線設定](references/connection.md)、[查詢與盤點讀取](references/query.md)、[CEF 欄位](references/cef-fields.md)。

初始化與查詢沿用同一份設定。既有 MCP 不另外索取 ES API Key；直接 API 使用執行環境的唯讀 Key。每個使用者 repo、Agent 和來源的資料各自放在 `.local/elasticsearch-query/<agent_id>/<source_id>/`，不寫回共用 skill。

程式只用 Python 3 標準函式庫。直接 API 支援有範圍、時間及欄位限制的常用 Query DSL；HTTP MCP 使用 server 提供的查詢介面。實際唯讀權限、資料範圍與欄位限制由服務端執行。

安裝方式：

```sh
npx skills add rulearena/elasticsearch-query
```

可用 `-a claude-code codex pi hermes-agent` 指定安裝對象；加 `-g` 安裝到使用者目錄。安裝給 Hermes 的例子：

```sh
npx skills add rulearena/elasticsearch-query --skill elasticsearch-query -g -a hermes-agent -y
```

安裝 skill 不會自動配置 MCP、安裝 Python 或建立認證。目前已通過 61 項隔離測試，使用虛構資料與模擬服務；另以僅含 `SKILL.md`、`scripts/`、`references/` 的副本通過初始化→查詢→盤點讀取流程；`tests/` 僅供開發維護，技能使用時不會執行。真實 ES／MCP 連線及服務端權限需在各使用者環境另外驗證。

已用 `skills@1.7.6` 從 GitHub 在隔離環境完成 Claude Code、Codex、Pi、Hermes 四個目標的專案安裝，以及 Hermes 全域安裝；必要檔案與原始碼一致，安裝副本通過 9 組命令列驗證。此驗證不代表已在四種 Agent 中完成 AI 操作驗收。

`setup.json` 使用第 3 版狀態，獨立綁定資料來源。`last_attempt` 記錄最近一次設定結果，`last_success` 保留最後成功驗證摘要。更新失敗會取消可用狀態；離線總覽、設備、索引與欄位查閱仍可讀歷史報告，並顯示最近失敗。缺少來源綁定的舊紀錄需重新執行 `setup`。
