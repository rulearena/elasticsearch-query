# CEF 欄位說明

本文件供查詢與解讀紀錄使用，不是完整 CEF 產生器或 parser 規格。
本文說明常見 CEF 欄位語意。不同解析流程可能改名、轉型或不保留欄位；實際查詢前仍要核對來源文件、欄位定義和資料樣本。

## 讀法與證據界線

CEF 是「表頭＋延伸欄位」的文字格式：

```text
CEF:Version|Vendor|Product|Device Version|Event Class ID|Name|Severity|Extension
```

前面可另有 syslog 前綴。表頭提供產品與事件種類，Extension 使用 `key=value`。
短名稱是線上 CEF 常見寫法，完整名稱是其標準語意名稱；ES 實際儲存名稱由解析流程決定。
標準文件、ES 欄位型別、實際欄位值是不同的證據，不可互相取代。

| 證據 | 能確認什麼 | 不能單獨確認什麼 |
| --- | --- | --- |
| CEF 文件 | 標準欄位的定義與對應 | 實際資料是否真的有填值 |
| ES 欄位資訊 | 欄位型別、可搜尋／可聚合性 | 欄位值的業務意思、資料完整度 |
| 實際紀錄及解析對應 | 該來源如何送出與轉換欄位 | 少量樣本不能代表所有產品與歷史版本 |

## 表頭

| 常見解析名稱 | 說明 |
| --- | --- |
| `cefVersion` | CEF 格式版本；`0`／`1` 是格式版本，不是設備軟體版本 |
| `deviceVendor` | 產生事件的廠商 |
| `deviceProduct` | 產生事件的產品；同一廠商可能有多種產品 |
| `deviceVersion` | 產品版本 |
| `deviceEventClassId` | 事件類型／簽章 ID；要結合 Vendor、Product、Version 解讀，不是每筆日誌的唯一 ID |
| `name` | 人類可讀的事件描述；仍需搭配動作與其他欄位 |
| `severity` | 表頭嚴重度；可能被 parser 轉成其他名稱。數字 0–3 低、4–6 中、7–8 高、9–10 很高；不能直接等同於實際攻擊或影響 |

## 動作、分類、次數

| CEF 短名稱／Key | 完整名稱 | 意思與查詢注意事項 |
| --- | --- | --- |
| `act` | `deviceAction` | 裝置採取的動作。`deny`、`accept` 等值由產品／connector 決定；結合產品與事件類型解讀 |
| `outcome` | `eventOutcome` | 結果，常見為 success／failure；不一定等於允許／拒絕 |
| `cat` | `deviceEventCategory` | 裝置的事件分類 |
| `reason` | `Reason` | 原因／錯誤碼；ES 大小寫與實際對應須確認 |
| `msg` | `message` | 補充描述。原始 CEF 也可能存於 `message`，兩者不可只靠名稱區分 |
| `cnt` | `baseEventCount` | 同一事件被觀察的次數，值為 1 時可省略；文件筆數與這個數值的加總不同 |
| `type` | `type` | 0 base、1 aggregated、2 correlation、3 action；不能將聚合／關聯紀錄當作獨立原始事件任意相加 |
| `externalId` | `externalId` | 來源裝置的事件 ID；是否可去重，需確認範圍、重設及唯一性 |
| `eventId` | `eventId` | ArcSight 指派的事件 ID；不能未驗證就假設所有來源或重送都共享唯一性 |

`deviceAction` 不等於 `event.action` 已有值。後者是另一套欄位命名（ECS）的動作欄位；是否轉換要看實際 pipeline。
`close`、`client-rst`、`server-rst`、`timeout` 不能直接算成 `deny`。

## 來源與目的

| CEF Key | 完整名稱 | 意思 |
| --- | --- | --- |
| `src` | `sourceAddress` | 來源 IP |
| `spt` | `sourcePort` | 來源埠 |
| `shost` | `sourceHostName` | 來源主機名稱 |
| `smac` | `sourceMacAddress` | 來源 MAC |
| `sntdom` | `sourceNtDomain` | 來源 Windows domain |
| `suser` | `sourceUserName` | 來源使用者；某些事件代表寄件者 |
| `suid` | `sourceUserId` | 來源使用者 ID |
| `spriv` | `sourceUserPrivileges` | 來源使用者權限 |
| `spid` | `sourceProcessId` | 來源程序 ID |
| `sproc` | `sourceProcessName` | 來源程序名稱 |
| `sourceServiceName` | 同名 | 來源服務 |
| `sourceDnsDomain` | 同名 | 來源 DNS domain |
| `sourceTranslatedAddress` | 同名 | NAT 後來源 IP |
| `sourceTranslatedPort` | 同名 | NAT 後來源埠 |
| `dst` | `destinationAddress` | 目的 IP |
| `dpt` | `destinationPort` | 目的埠 |
| `dhost` | `destinationHostName` | 目的主機名稱 |
| `dntdom` | `destinationNtDomain` | 目的 Windows domain |
| `duser` | `destinationUserName` | 目的使用者；某些事件代表收件者 |
| `duid` | `destinationUserId` | 目的使用者 ID |
| `dpriv` | `destinationUserPrivileges` | 目的使用者權限 |
| `dpid` | `destinationProcessId` | 目的程序 ID |
| `dproc` | `destinationProcessName` | 目的程序名稱 |
| `destinationServiceName` | 同名 | 目的服務；實際儲存欄位依解析流程核對 |
| `destinationDnsDomain` | 同名 | 目的 DNS domain |
| `destinationTranslatedAddress` | 同名 | NAT 後目的 IP |
| `destinationTranslatedPort` | 同名 | NAT 後目的埠 |
| `app` | `applicationProtocol` | 應用層協定，例如 HTTPS |
| `proto` | `transportProtocol` | 傳輸協定，例如 TCP／UDP |
| `in` | `bytesIn` | 流入位元組數；方向依來源定義核對 |
| `out` | `bytesOut` | 流出位元組數；不能當成封包數 |

來源 IP 不一定是攻擊者，目的 IP 不一定是受害者。NAT、代理、轉送與設備觀察方向會影響解讀。

## 設備與轉送者

| CEF Key | 完整名稱 | 意思 |
| --- | --- | --- |
| `dvc` | `deviceAddress` | 產生事件的設備 IP，不是連線來源 IP |
| `dvchost` | `deviceHostName` | 設備主機名稱 |
| `dvcpid` | `deviceProcessId` | 設備上的程序 ID |
| `dvcmac` | 需核對 | 先核對來源規格和實際解析欄位，不從縮寫自行推定用途 |
| `deviceExternalId` | 同名 | 設備識別碼 |
| `deviceDirection` | 同名 | 0 inbound、1 outbound；方向是相對於記錄設備 |
| `deviceInboundInterface` | 同名 | 進入介面 |
| `deviceOutboundInterface` | 同名 | 離開介面 |
| `dtz` | `deviceTimeZone` | 設備時區 |
| `agt` | `agentAddress` | ArcSight connector 的位址，不能當成原始來源 IP |
| `ahost` | `agentHostName` | connector 主機名稱 |
| `aid` | `agentId` | connector ID |
| `at` | `agentType` | connector 類型 |
| `atz` | `agentTimeZone` | connector 時區 |

多個 connector／轉送路徑可能帶入同一事件；不可假設不同索引就是互不重複的來源。

## 時間

| CEF Key | 完整名稱 | 意思 |
| --- | --- | --- |
| `rt` | `deviceReceiptTime` | 設備記錄的事件接收時間 |
| `start` | `startTime` | 活動開始時間 |
| `end` | `endTime` | 活動結束時間，例如 session 結束 |
| `art` | `agentReceiptTime` | connector 接收事件時間 |
| `mrt` | `managerReceiptTime` | manager 接收事件時間 |

CEF 時間可能是 epoch 毫秒，也可能是規格允許的文字格式。`@timestamp` 是儲存後的查詢欄位，不是 CEF 短名稱；它取自哪個原始時間，要查該來源的 parser。
傳送延遲可能讓「今天收到的資料」與「今天活動發生的資料」不同。

## 自訂欄位與 Label

| Key | 完整名稱 | 配對標籤 |
| --- | --- | --- |
| `cs1`–`cs6` | `deviceCustomString1`–`6` | `cs1Label`–`cs6Label` |
| `cn1`–`cn3` | `deviceCustomNumber1`–`3` | `cn1Label`–`cn3Label` |
| `cfp1`–`cfp4` | `deviceCustomFloatingPoint1`–`4` | 同號 `cfpNLabel` |
| `c6aN` | `deviceCustomIPv6AddressN` | 同號 `c6aNLabel`；摘要指出規格表格與 IPv6 章節對槽位有差異，不自行假定每個 N 都存在 |
| `deviceCustomDate1`、`2` | 同名 | 同號 `deviceCustomDateNLabel` |
| `flexString1`、`2` | 同名 | 同號 `flexStringNLabel` |
| `flexDate1` | 同名 | `flexDate1Label` |

例如 `cs1Label=PolicyName cs1=OfficeAccess` 才能解讀為規則名稱 OfficeAccess。
不同廠商、產品、版本或 connector 可能把不同資訊放在 `cs1`；文件中的建議對應不是所有來源都必然遵守的約定。
parser 可能把 Label 轉成實際欄位名稱，並做大小寫／命名轉換。查詢前要核對對應，而不是固定查某個槽位。

## HTTP 與檔案

| CEF Key | 完整名稱 | 意思 |
| --- | --- | --- |
| `request` | `requestUrl` | 請求 URL |
| `requestMethod` | 同名 | HTTP 方法 |
| `requestClientApplication` | 同名 | 用戶端應用／User-Agent |
| `requestContext` | 同名 | 請求來源內容，例如 Referrer |
| `requestCookies` | 同名 | Cookie；避免無必要讀取或顯示 |
| `fname` | `fileName` | 檔名 |
| `filePath` | 同名 | 檔案路徑 |
| `fileHash` | 同名 | 檔案雜湊 |
| `fsize` | `fileSize` | 檔案大小 |
| `fileType` | 同名 | 檔案類型 |
| `fileCreateTime` | 同名 | 建立時間 |
| `fileModificationTime` | 同名 | 修改時間 |

## 核對原始 CEF 時

- Extension 的值可含空白，不能直接用每個空白切成欄位。
- 表頭可有跳脫的 `\|`，不能不處理跳脫就以所有管線字元切割。
- 反斜線可寫為 `\\`；Extension 的等號可寫為 `\=`；換行可寫為 `\n`／`\r`。
- 原始訊息可能在 `message`、`event.original` 或其他來源欄位；先看實際資料。完整原文不一定一直保留。
- CEF Producer／Consumer 限制是事件產生規範；不能把標準短名稱要求誤套成 ES 只能查短名稱。
- 本文件未列出的欄位，先查現有欄位定義、原文與來源文件；不要自行猜測其意思。
