# netwhere

**Windows 本机流量走向工具**：记录每个程序的流量从哪里出去、去了哪里、用了多少。

- 数据来自系统的 ETW 事件（网络、DNS、进程三类），按程序记账，短连接也不会漏。
- 本机运行 Mihomo 内核时，再关联内核的连接信息，补上节点、域名和命中的规则。
- 只观测：不拦截、不修改流量，不抓包，不保存通信内容。
- 用 MoonBit（native 后端）编写，C 只用于调用 Windows API。

它能回答的问题，下面两个例子都是在作者机器上实测到的：

- 同一条 `git ls-remote`，在普通终端里走代理，在管理员终端里却直连并被重置。原因是两个终端的环境变量不同。
- 开启 TUN 后，支持 IPv6 的网站会经 IPv6 默认路由直接出去，完全绕过代理内核。

## 使用

```powershell
netwhere install                 # 注册后台采集进程（弹一次 UAC），登录时自动启动
netwhere status                  # 采集进程、代理内核、运行模式
netwhere trace -- git push       # 在当前终端运行命令，报告它整个进程树的流量走向
netwhere report                  # 今天各应用的流量：经节点 / 内核直连 / 绕过内核 / 局域网
netwhere report --7d --by node   # 近 7 天按节点汇总，并按倍率估算套餐消耗
netwhere unknown                 # 还没有归类的流量
netwhere classify example.com 工作      # 把域名或进程（xxx.exe）归到某个应用
netwhere rules list | add | remove
netwhere export --csv --30d --out usage.csv
netwhere uninstall [--purge]
```

`trace` 的输出示例：

```
process   destination                   entry       exit    up     down     conns  rule
curl.exe  tcp speed.cloudflare.com:443  proxy-port  HK 01   950 B  19.1 MB  1      Match
curl.exe  tcp speed.cloudflare.com:443  bypass      -       0 B    2.9 KB   1
```

没有安装采集进程时，`trace` 会降级运行：只显示进入代理内核的连接，并注明看不到直连流量。

## 统计口径

每份流量记两层：

| 层 | 取值 | 判断依据 |
|---|---|---|
| 入口（entry） | `proxy-port` 经代理端口进入内核 / `tun` 经 TUN 进入内核 / `bypass` 本机有内核但直接出网 / `direct` 本机没有内核时的直接出网 / `lan` 局域网 | 回环端口的监听者是否是代理内核（`GetExtendedTcpTable`）；目的地址走哪块网卡（`GetBestRoute2`） |
| 出口（exit） | 某个节点 / 内核直连 `DIRECT` / 拒绝 `REJECT` / 未知 `?` | 用源端口、进程名和时间窗口关联 Mihomo 的连接快照；快照没赶上的短连接，用 `/logs` 兜底 |

具体规则：

- **只记应用一侧的 socket。** 代理内核在回环和 TUN 网段上的流量是应用流量的镜像，不计；内核到节点的流量单独汇总，只用于对账。实测在 20 MB 下载中，与 Mihomo 的计数相差约 1 KB。
- **字节数包含 TLS 和 HTTP 开销。** 进程归属用 ETW 事件里的 `PID` 字段，而不是事件头里的进程号。
- **域名来源的优先级：** Mihomo 的 host > 本进程的 DNS 应答 > 全机的 DNS 应答 > 只显示 IP。
- **应用分类：** 用户规则优先；同一来源内，"进程 + 域名" > 只看进程 > 只看域名。内置规则导入自 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)（MIT）。
- **套餐消耗估算：** 只算出口为节点的流量。每个节点的流量乘以倍率，倍率可以在 `config.json` 里手工配置，或从节点名中的 `2x`、`x3`、`0.5x`、`2倍` 之类标记识别，都没有时按 1 倍计算。

## 架构与权限

```
netwhered.exe（管理员权限，登录时由计划任务启动，无窗口）
  ETW → 记账引擎 → %ProgramData%\netwhere\ledger.db（每 10 秒写一次）
  Mihomo /connections + /logs（WebSocket，断线自动重连）
        ▲ 读 ledger.db          │ 写 requests\*.json、config.json
netwhere.exe（普通权限）
```

- **只有采集进程提权。** 计划任务运行的二进制放在只有管理员能写的 `bin\` 目录。
- **用户可写的只有 `requests\` 和 `config.json`。** 提权进程只用 MoonBit 代码解析这些 JSON 文件，并逐项校验。
- **账本对用户只读。** 采集进程停止后，账本仍然可以读（靠一个设置了 `PERSIST_WAL` 的保活连接）。
- **`trace` 由普通权限的客户端在你自己的终端里启动命令。** 命令先以挂起状态启动；采集进程确认它的父进程确实是客户端之后，才恢复运行，因此一个字节都不会漏。
- **没有提权时降级运行：** 只使用 DNS-Client 和 Mihomo 的数据。

## 包

| 包 | 后端 | 内容 |
|---|---|---|
| `netaddr` | 全后端 | IP 地址和网段的规范化（ETW 输出未压缩的 IPv6，DNS 和 Mihomo 输出压缩形式） |
| `ledger` | 全后端 | 事件模型、规范化、录制格式、记账引擎、回放 |
| `mihomo` | 全后端 | `/connections`、`/logs`、`/configs` 解码 |
| `rules` | 全后端 | 域名和进程匹配、v2fly 数据格式、内置规则文件 |
| `mailbox`、`config`、`report`、`installer`、`scenario` | 全后端 | 信箱协议状态机、配置文件、输出格式、安装计划、场景校验 |
| `etw`、`route`、`sys`、`store`、`mihomo/client` | native | ETW 会话、IP Helper、进程与令牌、SQLite、WebSocket 客户端 |
| `cmd/netwhere`、`cmd/netwhered`、`cmd/rules-import`、`cmd/nw-route` | native | 命令行、采集进程、规则导入、路由诊断 |

## 开发

```powershell
moon check --target native
moon test --target native
moon build --target native --release
```

需要 moonc ≥ 0.10.20 和 MSVC。CI 运行 fmt、check、test 和 info 的一致性检查。

**录制场景（需要管理员权限，用来生成回放测试样例）**：在普通终端里运行下面的命令。每次运行弹一次 UAC，场景命令都在你自己的终端环境里执行。

```powershell
.\scripts\record-scenarios.ps1 -Mode system-proxy     # FlClash：开系统代理、关 TUN
.\scripts\record-scenarios.ps1 -Mode tun              # FlClash：开 TUN（fake-ip）、关系统代理
netwhere verify testdata\raw\tun.manifest.json        # 和预期的走向逐项对照
python -I scripts\sanitize_recording.py testdata\raw\tun.manifest.json testdata\scenarios
```

`testdata\raw\` 已加入 git 忽略。`testdata\scenarios\` 里是脱敏后的录制，`moon test` 会逐个回放并核对。

**内置规则：**

```powershell
git clone --depth 1 https://github.com/v2fly/domain-list-community $env:TEMP\dlc
moon run cmd/rules-import -- $env:TEMP\dlc\data --apps rules\apps.txt --out rules\builtin.txt --source "v2fly/domain-list-community@<commit>"
```

## 状态

**已完成且已测试**（CI 自动测试，或在作者机器上用普通权限实测过）：

- 地址规范化、事件规范化、录制格式、记账引擎（合成场景覆盖系统代理、TUN、IPv6 绕过、短连接日志兜底、端口复用、不一致标记）、增量写库。
- Mihomo 的快照、日志和配置解码；WebSocket 订阅。
- 规则匹配、v2fly 格式解析、规则导入（使用测试数据集）。
- SQLite 账本：含保活连接；"采集进程停止后只读用户仍能读取"已实测。
- 信箱协议（完整状态机），以及普通权限下的端到端流程。
- 所有命令行命令、降级 trace、路由与监听表查询。
- 普通权限下的录制：DNS-Client 和 Mihomo。

**已在提权实机上验证**（2026-11-13，FlClash / Mihomo）：

- 系统代理模式和 TUN（fake-ip）模式各 6 个场景，全部符合预期，包括"IPv6 绕过 TUN"。录制已脱敏，放在 `testdata/scenarios/`，由 `moon test` 回放。
- 定长解码和 TDH 逐字段对照：103,671 个字段，没有任何差异。没有丢失事件，现在默认使用定长解码。

**已完成，等待实机验证：**

- `install` 和 `uninstall`。
- 采集进程连续运行 24 小时；开销测量。

**计划中：** 托盘和图形界面（PLAN.md 第 8 节）。

## 已知限制

- 只支持 Windows。出口信息只支持 Mihomo；其他内核只能提供入口信息。
- 浏览器开启安全 DNS（DoH）时，直连流量只能显示 IP，无法显示域名。
- 降级模式看不到直连流量。普通权限下开启 DNS-Client 会话，要求账号属于 Performance Log Users 组。

## 许可

Apache-2.0。内置分类规则的数据来自 v2fly/domain-list-community（MIT）。
