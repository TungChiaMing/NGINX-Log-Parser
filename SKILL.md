# NGINX Log Parser — 專案架構說明

## 整體架構 (`project/app.py`)

`NginxLogAnalyzerApp` 是整個 Flask 應用的入口類別，負責：

- 建立 Flask app 實例，設定 `secret_key`（從環境變數 `SECRET_KEY` 讀取，預設為 `dev-secret`）
- 確保 `sessions/` 上傳目錄存在
- 掛載三個 Blueprint：

| Blueprint | URL 前綴 | 模組 |
|---|---|---|
| `log_parser_router` | `/log_parser` | `project.log_parser.router` |
| `nginx_profile_router` | `/nginx_profiles` | `project.nginx_profiles.router` |
| `config_scanner_router` | `/config_scanner` | `project.config_scanner.router` |

- 在 `_register_routes()` 中直接定義全域路由：`/login`、`/logout`、`/`（主選單）

---

## 功能一：Log Parser (`project/log_parser/`)

### 用途
從遠端 Nginx 伺服器抓取 access log，依時間區間過濾後輸出 `combined.log`（原始過濾結果）與 `summary.log`（HTTP 狀態碼 / Client IP 統計）。

### 路由 (`router.py`)

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET/POST | `/log_parser/` | 查詢表單；POST 後觸發分析，成功則 redirect |
| GET | `/log_parser/results/<session_id>` | 從磁碟載入 `meta.json` 並顯示永久結果頁 |
| GET | `/log_parser/saved` | 列出所有歷史查詢紀錄 |
| POST | `/log_parser/saved/delete/<session_id>` | 刪除指定歷史紀錄（含檔案） |
| GET | `/log_parser/download/<session_id>/<path:filename>` | 下載 combined.log 或 summary.log |

### 分析流程 (`parser.py`)
1. `fetch_remote_log_filenames` — 爬取遠端目錄列表（`<pre>` tag），以日期過濾出需要下載的 `.log` / `.log.gz` 檔名
2. `stream_and_filter_log` — 逐行串流下載，依時間戳記過濾、統計 HTTP status code 與 Client IP
3. `run_nginx_log_analysis` — 主入口，串接上述步驟，輸出兩個檔案回傳路徑

### 持久化儲存
結果存於 `saved_results/<session_id>/`：
```
saved_results/
  <session-uuid>/
    meta.json          ← 查詢參數 + 時間戳記 + log 完整內容
    <url_id>/
      combined.log
      summary.log
```

### 歷史紀錄的使用者隔離

> **目前行為：所有登入使用者共享同一份歷史紀錄。**

原因：
- `save_meta()` 儲存的 `meta.json` 只包含 `session_id`、`created_at`、`form_data`、`results`，**不記錄執行查詢的 username**
- `list_saved_sessions()` 直接掃描整個 `saved_results/` 目錄，不依使用者過濾
- 任何登入者都可以查看、刪除其他人建立的紀錄

若未來需要改為各自獨立，需在 `meta.json` 中加入 `"username"` 欄位，並在 `list_saved_sessions()` 與 `delete_saved()` 路由加上 `session.get("username")` 的比對過濾。

---

## 功能二：Config Scanner (`project/config_scanner/`)

### 用途
輸入伺服器名稱，自動對 `http://<server>.example.com/nginx_conf/` 發送 HTTP 請求，遞迴爬取 `.conf` 檔案並分析 Nginx 配置內容，結果儲存為 Profile JSON。

### 路由 (`router.py`)

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET/POST | `/config_scanner/` | 輸入伺服器名稱表單；掃描完成後 redirect 至 Nginx Profiles 列表 |

### 掃描邏輯 (`scanner.py`)
- `find_conf_files_and_process` — 遞迴爬取目錄結構，識別 `.conf` 檔（或具有 Nginx 關鍵字的純文字檔），分析每個檔案
- `_analyze_conf_content` — 用 regex 分析單一 conf 內容，提取：
  - `access_log off` 設定
  - port 80 / 443 server 指令
  - 特殊 port（211, 214, 1433, 8082, 8083, 445）
  - 其他 port 的 server 指令
  - 所有 `listen` 指令
- `scan_nginx_log_directory` — 額外掃描 `/nginx_logs/` 目錄，提取 log 檔名與日期
- `preserve_existing_memo` — 掃描前先讀取舊 profile 的 memo 欄位，防止覆蓋人工備註
- `save_profile` — 將掃描結果寫入 `static/profiles/<server_name>.json`

---

## 功能三：Nginx Profiles (`project/nginx_profiles/`)

### 用途
讀取 `static/profiles/` 中所有 Profile JSON，提供列表瀏覽、搜尋、Fab 篩選、upstream 搜尋，以及單一伺服器詳細頁與 memo 編輯。

### 路由 (`router.py`)

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/nginx_profiles/` | 分頁列表，支援 `search`、`fab_filter`、`upstream_search` 查詢參數 |
| GET | `/nginx_profiles/<server_name>` | 單一伺服器詳細掃描結果頁 |
| POST | `/nginx_profiles/update_profile_field` | AJAX 更新 memo 欄位（JSON API） |

### 篩選邏輯 (`filter.py`)
依序執行四個步驟：
1. `load_profiles(fab_filter)` — 從磁碟載入，依 Fab 正則篩選（`F12`~`F23` 對應伺服器名稱前綴）
2. `apply_upstream_filter` — 依 upstream IP/主機名稱或 port 搜尋
3. `apply_name_filter` — 依伺服器名稱關鍵字搜尋
4. `format_profile_for_display` — 整合 port 資訊、log 最新日期等供模板使用
5. `paginate_profiles` — 每頁 10 筆分頁

---

## HTML 模板 (`project/templates/`)

| 模板檔 | 對應功能 |
|---|---|
| `login.html` | 登入頁（全域） |
| `main_menu.html` | 主選單（全域） |
| `log_parser.html` | Log Parser 查詢表單 |
| `log_parser_result.html` | Log Parser 結果頁（含 keyword 過濾、下載連結、永久連結資訊） |
| `log_parser_saved.html` | Log Parser 歷史紀錄列表（含刪除） |
| `config_scan.html` | Config Scanner 輸入表單 |
| `config_scan_result.html` | Config Scanner 掃描結果（完整頁） |
| `config_scan_result_partial.html` | Config Scanner 結果（嵌入於 Profile 詳細頁） |
| `nginx_profiles_list.html` | Nginx Profiles 分頁列表，支援多種篩選 |

---

## 靜態 Profile 儲存 (`static/profiles/`)

- 每個伺服器存一個 JSON 檔：`<server_name>.json`
- 由 Config Scanner 掃描後自動寫入或覆蓋（memo 欄位除外，會保留）
- 由 Nginx Profiles 功能讀取、展示、供 memo 欄位即時 AJAX 編輯
- JSON 結構包含：`server_name`、`full_server_name`、`config_base_url`、`file_analysis`（各 conf 分析）、`summary`（彙總計數）、`log_dir_info`（log 目錄資訊）、`memo`（人工備註）

---

## 共用工具 (`project/utils.py`)

| 函式 / 變數 | 說明 |
|---|---|
| `PROFILE_SAVE_DIR` | `static/profiles/` 路徑常數 |
| `login_required` | Flask session 登入檢查 decorator |
| `read_text_file_safe` | 安全讀取文字檔（最多 200 KB，UTF-8 錯誤忽略） |
| `create_profile_save_dir` | 確保 `static/profiles/` 目錄存在 |
