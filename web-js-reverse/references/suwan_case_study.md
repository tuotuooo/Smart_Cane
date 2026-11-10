# 落地案例：SUWAN 61 站采购公告监控

> 本文件是 `../SKILL.md`（网页 JS 逆向通用 SOP）在**一个垂直场景**的完整落地记录：多站点（61 站）采购公告增量监控（抓列表 → 去重 → 抓正文 → DeepSeek 解析 9 字段 → IT 类发邮件 → 回写台账）。
> 读这份，看「通用 SOP 的五步」是怎么在真实站点上跑通的；26 条坑是 SOP 各步骤在实战中的具体翻车与解法。

## 双来源配置（SOP·Step5「不污染生产配置」的实例）

- 生产 `config.json` 的 `sites`（46 站）：**含明文密钥（DeepSeek key / SMTP 密码 / 真实邮箱）**，**永不覆盖**。
- 代码内 `EXTRA_SITES`（15 站）：新增站点全写这里，加载时按 `code` 去重**追加**到 config 之后；若 config 已有同 `code` 则以 config 为准。
- 代码内 `SITE_CONFIG_FIXES`：个别站点的 `list_path`/`column_id` 修正，运行时套用，**不用动生产 config**。
- 收益：换机器只需覆盖主程序，生产 config（密钥 + 台账）完全不动。

## 五步法在 SUWAN 的对应

| SOP 步骤 | SUWAN 落地实例 |
|---|---|
| Step1 抓 HAR | STFI：翻页抓到 `POST /dwr/call/plaincall/typePageContentAjax.getNewsList.dwr`；SGJART：抓到外链 `czju.suzhou.gov.cn/zfcg/content/searchkey.action` 的 JSON 响应 |
| Step2 下载静态资源分析 | STFI：下载 `dwr/interface/typePageContentAjax.js` 读方法签名（需 `site_id`+`column_id`）；NUAZJ：`curl -w` 对比 `/8362`(302) vs `/7032`(200) 选定活路径 |
| Step3 分析契约与反爬 | 判定 jeecms / sudy / DWR / Struts JSON / Vue SPA；STFI 属 JSLUIC、HHU 等 4 站属瑞数 |
| Step4 复现真实请求 | STFI：复刻 DWR 文本协议 POST（带 `__jsluid_s` 预热 cookie）拿 30 条；SGJART：`POST searchkey.action` 带 `{title,page,rows:15}` 拿 rows；老 TLS 站自定义 SSLContext |
| Step5 固化代码 | 新增 5 站（NITH/ZDUA/SGJART/STFI/JUTI）走 `EXTRA_SITES`；3 个新 platform 分支（custom_czju/custom_zdua/custom_juti）全补四段 |

## 踩坑手册（现象 → 根因 → 解法）

### 反爬 / WAF

| # | 现象 | 根因 | 解法 |
|---|---|---|---|
| W1 | 412 挑战页（不是验证码） | 瑞数 ZTrust JS-VMP 反爬（指纹 `r='m'`/`$_ts/$_ss`/随机名 HttpOnly cookie/`X-ZTrust-Upstream-Latency`） | 必须真跑浏览器；静态逆向/伪造请求头均无效 |
| W2 | 伪造全套 Chrome 头仍 412 | 差异不在 HTTP 头层 | 放弃头伪造 |
| W3 | 回放 412 下发的 cookie 仍 412 | 那个随机名 cookie 是种子不是令牌 | 不回放 |
| W4 | 412 → VMP 算出 cookie → reload → **400 空 body** | **CDP / `add_init_script` 的自动化痕迹被 VMP 写进环境指纹** | 改用完全独立浏览器进程，**不建 CDP、不注入脚本**：`--headless=new --dump-dom --virtual-time-budget=20000 --user-data-dir=<独立profile> --no-proxy-server` |
| W5 | 挑战页误判 | 真实页残留 `r='m'`，或成功页无 `<title>`（SEU DataTables 渲染页） | 综合 `$_ts/$_ss`+页面长度+title 判；无 title 时看去脚本后可见文本量 <200 才判挑战 |
| W6 | STFI 的 DWR 静默返回空（`maxPages:0`） | JSLUIC WAF（`__jsluid_s`）非挑战页、静默空响应 | 预热一次 GET 取 cookie，再 POST DWR（Referer/Origin 正常放行） |
| W7 | NUAZJ 返回 581B「网站正在维护中」软 200 | 站点侧整站维护，**非**路径/解析问题 | 识别并标注，别再重探栏目 |

### 解析

| # | 现象 | 根因 | 解法 |
|---|---|---|---|
| P1 | sudy 站长期 0 条 | `Accept-Encoding: br` 后 NCC/NJTS 真返回 Brotli，Python 没装 brotli → 全乱码 | 改 `gzip, deflate`；**判 0 条先 `curl -I` 看 `Content-Encoding`** |
| P2 | 详情失败仍入库 = 永久丢数据 | 空 `raw_text` 写了去重键 | 按 `raw_text` 非空过滤，失败下轮重试 |
| P3 | 兜底把父容器文本当标题（SZJSJT 15 条串成 1 条） | 上溯 3 层命中整列 `<ul>` | 标题永远取锚文本，父节点只补日期 |
| P4 | 政务 CMS 静态列表 0 条 | `/type/{id}.html` 列表由 DWR 异步渲染 | 逆 `dwr/interface/xxx.js` + 列表页内联 script + `dwr/engine.js` 的 `_serializeObject`；**参数必须 `Content-Type: text/plain` + 换行 kv + `Object_Object:{k:reference:c0-eN}`** |
| P5 | CUCN 整站 488B 空壳 `<div id="app">` | 官网是 Vue SPA，数据走独立后端 | 逆后端 `wap.cucn.edu.cn/cucneduapi`（列表/详情，毫秒时间戳） |
| P6 | JSSJ Python 握手失败（curl/浏览器能连） | 老政务站只支持 `TLS_RSA_WITH_AES_128_CBC_SHA` 且 DHE 参数过小，OpenSSL3 默认拒 | 自定义 `SSLContext` + `set_ciphers("AES128-SHA:@SECLEVEL=0")` + `CERT_NONE`，**只对该站 opener 生效** |
| P7 | 政务站同名空 `div.content` → 正文 0B | 模板占位 | 容器文本 <80 字符回退 body |
| P8 | jszbcg 全量 400 | 两套主键两套 API：`bulletinType` 是**数字**非 `TenderBulletin` | 32 位 hex 走 `DataGatewayApi/.../BulletinType/{数字}/ID/{hex}`；纯数字 ID 走 `DataSyncApi/{Type}/id/{num}` |
| P9 | ccgp.gov.cn https 403 / http 200 | 同 URL 两种 scheme 结果不同 | URL 归一化 http；403/404 重试 3→1 |

### 架构 / 部署（最实战的坑）

| # | 现象 | 根因 | 解法 |
|---|---|---|---|
| D1 | **`--scan` 永远报「已有进程持锁，本次跳过」，重启亦然** | 单实例锁用 `fcntl.flock`；**容器/overlayfs 的 `/tmp` 上 flock 抛 OSError 被误判占用** | 改为**可移植 PID 锁文件**：`os.open(lock, O_CREAT|O_EXCL|O_WRONLY)` 原子建锁记录 PID；仅当 PID 存活才跳过；残留死锁自动清理重试 |
| D2 | `import schedule` ModuleNotFoundError | 运行解释器（系统 `python3`）缺 `schedule`；生产 venv 全装齐 | 用 venv 跑；或 `pip install schedule requests beautifulsoup4` |
| D3 | 瑞数站 412→400（Linux 上） | UA 与真实浏览器版本不自洽（旧脚本硬套 Windows UA） | 在 Linux 执行 `chromium --version` 自动生成同版本 X11 UA |
| D4 | 浏览器崩（Docker/小内存） | `/dev/shm` 太小（64MB） | 启动加 `--disable-dev-shm-usage` |
| D5 | 本机 PyPI 被墙，装不了 requests | 沙箱镜像 no package | 用 `urllib`+`bs4` 自写探针；或 `curl .whl` + `pip install --no-index --find-links` |
| D6 | 覆盖 config.json 丢密钥/破坏台账 | config 含密钥 + CSV 去重键 | **部署只覆盖主程序 + 过站模块（必要时启动脚本），绝不碰 config/CSV/log** |
| D7 | 覆盖后旧 `--watch` 仍跑旧代码 | 进程内存中是替换前的旧逻辑 | 覆盖后 kill 旧进程、用新文件重启 |

### 数据质量 / 边界

- 软 200 维护页（NUAZJ）不是 bug，别重探。
- 空壳/转载壳（NIIT 68B、JSCVC 235B）是站点发布方式限制，非解析 bug。
- **聚合源（ccgp.gov.cn 全国站、qianlima.com 商业站）不是单校采购点，排除**，别试图接入。
- 混栏目必须配 `title_keywords` 过滤（NJPU 9→1、JUTI），否则招生简章等进台账。
- JSSJ 栏目最新公告 2026-03-16，疑似学校改在省平台发布、站内不再同步——数据源限制，非解析器问题。

## 接入新站 7 步法（对齐 SOP 五步）

1. **抓 HAR**：DevTools 复现列表/翻页/详情，导出 HAR，定位真接口与发起 JS。
2. **本地下载静态资源**：`wget -r`/`curl` 扒站，grep 找接口路径、参数构造、WAF cookie 注入点，必要时反混淆。
3. **判定后端与反爬**：jeecms/sudy/vsb/DWR/Vue SPA/Struts JSON；JSLUIC（可预热绕过）/瑞数（必用浏览器）。
4. **复现真实请求**：`urllib`/`requests` 1:1 复刻 HAR，验证绕过 WAF、老 TLS、编码回退、分页/详情。
5. **写 platform 四段**：`fetch_page`/`parse`/`fetch_detail`/`extract_text` 全补，别漏 `fetch_detail`。
6. **写代码内扩展区**：新站全进主程序，不动生产 config。
7. **离线验证 → 生产复核**：`py_compile` + import-free 测试 → 生产自检（过站 N/N）+ 全量扫描逐站条数。

## 接手 / 部署 SOP

1. 读主程序内的平台分支与 FIXES 注释。
2. 补依赖 → 过站模块自检（目标 4/4）→ 测试 DeepSeek/SMTP → 全量扫描。
3. **替换清单**：只覆盖主程序 + 过站模块（若启动脚本是 Windows CRLF 拷的，`sed -i 's/\r$//'`），用 **venv 解释器**跑；**绝不碰 config/CSV/log**。
4. 覆盖后 kill 旧 `--watch` 用新文件重启。
5. cron 必须写解释器绝对路径；systemd `Environment=` 含空格要引号。

## 关键文件

- 主程序（含 `EXTRA_SITES` / `SITE_CONFIG_FIXES` / 各 platform 分支 / PID 锁）。
- 过站模块（瑞数过站：`--dump-dom` 无 CDP 方案；UA 自动对齐）。
- 启动脚本（可选：cd + venv 解释器）。
- `config.json`（含密钥，**不入库`）/`config.example.json`（脱敏模板）。
- 运行期产物 `announcements.csv` / `monitor.log`：**不入库**。
