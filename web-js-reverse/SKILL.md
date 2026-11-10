# 网页 JS 逆向 SOP（Web Traffic Reverse）

> 与 `android-https-capture`（App↔服务器抓 HTTPS）**同源**：对象都是「网络流量」，只是来源从 App 变成浏览器。本件覆盖「前端异步渲染 + 后端带反爬/WAF」的网页，目标是把站点逆向成可稳定抓取的接口。

## 适用对象

任何「前端拉数据、后端藏接口」的站点：采购/招标公告、**新闻列表**、政务公开、聚合页、SaaS 后台列表……

**不适用**：纯静态 HTML（直接 `requests` 即可，无需逆向）；需要登录态且接口完全在服务端鉴权的闭站（需先解决登录）。

## 核心闭环

```
抓得到真数据  →  解析得出来  →  生产可用、可维护、可增量
```

这套方法论不绑定业务，是「通用网页 JS 逆向」能力本身。落地案例见 `references/suwan_case_study.md`（61 站采购监控把它跑了一遍）。

## 五步工作流（怎么完成）

### Step 1 — 抓 HAR（捕获真实流量）

**目的**：拿到浏览器「真正发出去、真正收回来」的请求原貌，而不是肉眼看页面猜接口。

- DevTools → **Network** → 勾选 **Preserve log**（翻页/跳转不丢历史）。
- 复现目标操作：打开列表页 → 翻第 2 页 → 点开一条详情。
- 右键任意请求 → **Save all as HAR with content**（含 request/response body）。
- 在 HAR 里重点看：
  - **XHR / Fetch** 类型（真正的接口，不是 `.js`/`.css`/图片）；
  - **Initiator** 列（哪个 JS 函数发起的，定位前端调用点）；
  - **Request**：Query、Body、`Cookie`/`Referer`/`Origin`/自定义头；
  - **Response**：数据结构（JSON / DWR 文本 / HTML 片段）。
- 进阶：HTTPS 解密用 **Charles / Fiddler**；移动端用同款代理或手机 DevTools 远程。

### Step 2 — 本地下载 JS / HTML 静态资源（离线分析）

**目的**：把站点「扒」到本地，脱离浏览器反复硬刷，用编辑器 + grep 精读前端逻辑、找参数来源。

```bash
# 整站镜像（按需）
wget -r -np -k -E -p -l 2 "https://site.example/column/list" -P ./mirror
# -r 递归 -np 不跳父级 -k 改相对链接 -E 加 .html -p 含依赖 -l 2 深度

# 单页 + 依赖 JS
curl -s "https://site.example/list" -o list.html
# 从 list.html 里抠出 <script src>，逐个 curl 下来

# 离线 grep 找接口 / 参数构造 / WAF cookie 注入点
grep -rn "getNewsList\|searchkey.action\|/dwr/\|sign\|token\|_ts\|nonce" ./mirror
```

- **反混淆 / 格式化**：压缩 JS 用浏览器 Sources 面板 **Pretty print**，或本地 `npx esbuild x.js --format=esm > x.pretty.js`；定位加密/签名函数。
- **找「参数从哪来」**：翻页 `pageSize/currentPage`、签名 `sign/token`、时间戳、WAF cookie（`__jsluid_s`）在哪一步被写入、DWR 的 `Object_Object:{...}` 实参如何在列表页内联 script 里拼出来。

### Step 3 — 分析接口契约与反爬机制

**目的**：从 HAR Response 提炼字段映射，判定「后端类型」和「反爬类型」，决定技术路线。

- **字段映射**：`s0.xwbt`=标题 / `s0.xwdz`=链接 / `s0.fbsj`=日期（DWR）；`rows[].TITLE` / `RELEASE_TIME`（JSON）；`<dd cid>` / `<span class=date>`（HTML）。
- **判定后端类型**：
  - jeecms：`<dl class=llist>` / `<dd cid>` / 日期路径 `/{YYYYMMDD}/{id}.html`
  - sudy / vsb：列表由 JS 异步填充
  - DWR：`/dwr/call/plaincall/...` 文本协议
  - Vue SPA：整页 `<div id=app>` 空壳，数据走独立后端
  - Struts JSON：`.action` 返回 `{data:[...]}`
- **判定反爬 / WAF**：决定能否纯请求层解决（见下节）。

### Step 4 — 复现真实请求（本地重放验证）

**目的**：用标准库（`urllib`）或 `requests` 复刻 HAR 里的请求，验证不依赖浏览器也能拿到一致数据。

- **复刻请求**：URL + Headers（含 `Cookie`/`Referer`/`Origin`/`X-Requested-With`）+ Body，1:1 对齐 HAR。
- **绕过 WAF**：
  - JSLUIC（`__jsluid_s`）：先发一次 `GET` 列表页取 `Set-Cookie`，再带它 `POST` 接口。
  - 瑞数 ZTrust：请求层无效，**起独立浏览器进程**过（`--dump-dom --virtual-time-budget`，无 CDP 注入避免 VMP 指纹）。
- **老 TLS**：政务老站只支持弱套件且 DHE 参数过小，OpenSSL3 默认拒 → 自定义 `SSLContext` + `set_ciphers("AES128-SHA:@SECLEVEL=0")` + `CERT_NONE`，**只对该站生效**。
- **编码回退**：详情页可能 GBK，用 `gb18030` 兜底，否则中文乱码。
- **DWR wire format 必读**：参数必须 `Content-Type: text/plain` + **换行分隔的 kv** + `c0-param2=Object_Object:{pageSize:reference:c0-e1, currentPage:reference:c0-e2, ...}`，写成普通 form 或 `key=value&` 都返回 Error。
- **验证闭环**：单条请求拿到结构化数据 → 分页 → 详情页正文提取 → 字段解析正确。

### Step 5 — 固化进代码

**目的**：把验证过的接口 + 解析 + 绕过逻辑写进生产，且**不污染生产配置**。

- 新增一个后端 CMS，必须同时补 **4 处分支**（否则详情落兜底 `KeyError`）：`fetch_page` → `parse_announcements` → `fetch_detail` → `extract_text`。
- 新站点优先写进**代码内的站点扩展区**（加载时按 `code` 去重追加到生产配置之后），**生产配置文件完全不动**（含密钥 + 台账去重键）。
- 个别路径/栏目修正走**代码内 FIXES 区**，运行时套用，不碰生产配置。
- 上线前三关：`py_compile` → 离线 import-free 测试 → 生产自检（浏览器过站 N/N）+ 全量扫描逐站条数复核。

## 反爬类型谱与通用解法

| 类型 | 现象 | 解法 |
|---|---|---|
| JSLUIC（`__jsluid_s`） | DWR/接口静默返回空 | 预热一次 GET 取 cookie，再带 cookie POST |
| 瑞数 ZTrust（412 VMP） | 412 挑战页、随机名 HttpOnly cookie、`r='m'`/`$_ts` | 必须真浏览器；**不要建 CDP / 不注入脚本**，否则 VMP 把自动化痕迹写进指纹导致 400 |
| 老 TLS（弱套件 / 小 DHE） | Python 握手失败，curl/浏览器能连 | 自定义 `SSLContext` 单站生效 |
| Brotli 编码 | 声明 `Accept-Encoding: br` 后服务端真返回 br，解析全乱码 | 改 `gzip, deflate`；判 0 条先 `curl -I` 看 `Content-Encoding` |
| 软维护页（软 200） | 站点返回「网站维护中」小页面 | 站点侧维护，非解析问题，标注别重探 |

## 工程化通用原则

- **platform 四段式分发**：`fetch_page` / `parse` / `fetch_detail` / `extract_text` 全补，漏 `fetch_detail` = 经典坑。
- **三层降级**：真 API → 静态 HTML 解析 → 最后才浏览器过 WAF。
- **去重复合键 + 失败不入台账**：空正文的失败项不写去重键，否则永久占键、永不重试。
- **密钥环境变量优先、配置回退**：`DEEPSEEK_API_KEY` / `SMTP_PASSWORD` 等不进代码。
- **单实例锁用可移植 PID 锁文件，别用 `flock`**：容器/overlayfs 的 `/tmp` 上 `flock` 抛 OSError 会被误判「已有实例在跑」，导致任务永远跳过、重启也没用；改用 `os.open(O_CREAT|O_EXCL|O_WRONLY)` 原子建锁记录 PID，仅当 PID 存活才跳过，残留死锁自动清理。
