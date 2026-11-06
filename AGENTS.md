# elasticsearch-query 專案指引

## 專案範圍

- 本 repo 本身就是一個可安裝 skill；`SKILL.md`、`scripts/`、`references/` 直接放在根目錄，不再增加 `skills/` 容器。
- 首次設定、查詢說明、盤點腳本和必需參考文件都放在該 skill 內。
- 不加入 webhook、SOC 執行服務、案件系統、排程管理或其他可安裝技能。
- 工作範圍限目前 repo。讀取或修改其他位置前，必須取得當前對話對該精確路徑的授權。

## 連線和資料

- 支援既有 MCP、本機 MCP、Streamable HTTP MCP 和直接 ES API。
- 已有 MCP 時沿用它，不額外索取 ES API Key，也不因工具不足自行改走另一條連線。
- 遠端 HTTP MCP 必須使用 HTTPS；本機 HTTP 只接受回環位址且不得帶 Token。
- 服務端負責執行唯讀、索引／資產範圍和欄位限制。
- 資產資料只在需要時透過最小權限 MCP／API 按需讀取，不預先猜測或下載全部資產。
- 共用 skill 和程式；各 repo、Agent、資料來源分開保存 profile、盤點和狀態，放在使用者 repo 的 `.local/elasticsearch-query/<agent_id>/<source_id>/`。
- 公開範例只用虛構值，不放憑證、真實設定或現場資料。
- 設備以 CEF `deviceAddress` 為主。資產分區和用途只用已確認資料；未知就標示未知。

## 文件與驗證

- 使用繁體中文白話說明，先說結果和影響，區分已實作與未驗證。
- 讓 skill 安裝後能取得自己執行所需的所有檔案；不可依賴另一個 skill 已安裝。
- 修改腳本或文件路徑後，檢查引用、封裝位置、scope 和錯誤狀態。
- 發布前在隔離環境驗證乾淨安裝、首次設定、查詢、重跑與資料隔離；開發測試放在 `tests/`。
- 未實際驗證前，不宣稱已可安裝、可連線或已發布。
