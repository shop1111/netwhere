# netwhere

**Windows 本机流量走向工具**：记录每个程序的流量从哪里出去、去了哪里、用了多少。

- 数据来自系统的 ETW 事件（网络、DNS、进程三类），按程序记账，短连接也不会漏。
- 本机运行 Mihomo 或 sing-box 内核时，再通过它的 Clash API 关联连接信息，补上节点、域名和命中的规则。
- 连接没走代理时，给出候选原因、所依据的事实和确定程度；依据不够时直接写"未判定"。
- 每个结论都标明可信程度：出口是怎么关联上的、哪段时间没采到、套餐估算的上下限（见[可信边界](#可信边界)）。
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

有连接绕过内核时，`trace` 在表格后列出候选原因。下面是 `testdata/scenarios/tun` 录制（TUN 模式，`curl -6 --noproxy *`）的结果；实时 `trace` 还会附上当前路由经过的网卡：

```
process   destination                   entry   exit  up     down    conns  rule
curl.exe  tcp speed.cloudflare.com:443  bypass  -     697 B  4.8 MB  1

why it bypassed the core (candidate causes; "likely" depends on what the program does internally):
  tun-no-ipv6 (certain): TUN carries only IPv4; IPv6 traffic leaves through the physical adapter
      - destination tcp speed.cloudflare.com:443 ([2606:4700:7::da]) is IPv6
      - the TUN adapter has no global IPv6 address
      applies to: curl.exe tcp speed.cloudflare.com:443
```

出口列的标记：`?` 进了内核但没有关联到内核记录；`~` 关联到多条记录且出口不一致（显示时间最近的那条，但不计入已知节点）；`!` 进了 TUN 却始终没有内核记录。`trace` 末尾还会列出这段时间 Mihomo 连接是否断过、是否丢过事件。

没有安装采集进程时，`trace` 会降级运行：只显示进入代理内核的连接，并注明看不到直连流量。

## 排障：为什么没走代理

netwhere 能看到"绕过了"，看不到程序内部为什么这样决定。所以它只给**候选原因**，每条都列出依据的事实，并标明确定程度：`certain` 由观测事实直接推出；`likely` 与事实相符，但取决于程序内部行为；`undetermined` 没有规则成立，只列事实，不下结论。

| 原因 | 成立条件（均为观测到的事实） | 确定程度 |
|---|---|---|
| `bound-off-tun` | 路由指向 TUN，但连接的本地地址不在 TUN 网段（程序绑定了物理网卡） | certain |
| `tun-no-ipv6` | TUN 开启，目的地址是 IPv6，TUN 网卡没有全局 IPv6 地址 | certain |
| `route-excluded` | TUN 开启，但到该地址的路由不经 TUN（route-exclude、更具体的路由、strict-route 关闭） | likely |
| `proxy-not-configured` | TUN 和系统代理都关，命令环境里没有代理变量 | certain |
| `udp-not-proxied` | 只开系统代理，连接是 UDP（QUIC、DNS） | certain |
| `no-proxy-match` | 目的地命中 `NO_PROXY` 或系统代理例外列表（列出命中的条目） | likely |
| `mixed-in-process` | 同一进程的其他连接走了代理端口 | likely |
| `no-proxy-config` | 系统代理开着，命令环境没有 `HTTP(S)_PROXY`/`ALL_PROXY`（git 还会查 `http.proxy`） | likely |
| `no-core` | 没有代理内核在运行 | certain |
| `undetermined` | 以上都不成立 | — |

依据来自：命令的环境变量（`trace` 的命令继承当前终端的环境）、当前用户的系统代理设置（注册表）、git 的全局配置、Mihomo `/configs` 和网卡表（TUN 是否开启、有没有 IPv6）、`GetBestRoute2`（到目的地址的路由）。这些都在普通权限下读取。看不到的：命令行参数（例如 `curl --noproxy *`）和程序自己的配置文件，所以这类情况会落到 `likely` 或 `undetermined`。

`netwhere verify` 核对录制场景时也会打印每个场景的诊断结果，`moon test` 对两份真实录制的诊断结果做了快照断言。

## 统计口径

每份流量记两层：

| 层 | 取值 | 判断依据 |
|---|---|---|
| 入口（entry） | `proxy-port` 经代理端口进入内核 / `tun` 经 TUN 进入内核 / `bypass` 本机有内核但直接出网 / `direct` 本机没有内核时的直接出网 / `lan` 局域网 | 回环端口的监听者是否是代理内核（`GetExtendedTcpTable`）；连接的本地地址是否在 TUN 网段；目的地址走哪块网卡（`GetBestRoute2`） |
| 出口（exit） | 某个节点 / 内核直连 `DIRECT` / 拒绝 `REJECT` / 未知 `?` / 歧义 `~` | 用源端口、进程名和时间窗口关联内核 Clash API（Mihomo、sing-box）的连接快照；快照没赶上的短连接，用 `/logs` 兜底。每条连接记下关联方式：`snapshot`、`log`、`ambiguous`、`none` |

具体规则：

- **只记应用一侧的 socket。** 代理内核在回环和 TUN 网段上的流量是应用流量的镜像，不计；内核到节点的流量单独汇总，只用于对账。实测在 20 MB 下载中，与 Mihomo 的计数相差约 1 KB。
- **字节数包含 TLS 和 HTTP 开销。** 进程归属用 ETW 事件里的 `PID` 字段，而不是事件头里的进程号。
- **域名来源的优先级：** 内核报告的 host > 本进程的 DNS 应答 > 全机的 DNS 应答 > 只显示 IP。
- **sing-box 与 Mihomo 的差异：** sing-box 的 Clash API 字段与 Mihomo 基本一致（源端口、`chains` 顺序、开始时间），区别在于：
  - 只给 `processPath`，且默认不查进程（`find_process` 关闭时为空），关联时就只靠源端口和时间窗口；
  - 一个连接的日志分成"入站来源 / 入站目的 / 出站"三行，按连接 id 拼起来；日志里写明出站类型，自定义名字的直连出站（例如 `我的直连`）由此识别为 `DIRECT`；从没在日志里出现过的标签，只有 `direct`、`block` 这两个默认名会被当作直连 / 拒绝，其余都算节点；
  - 规则只在快照里有（`rule_set=... => route(...)` 或 `final`），只靠日志关联上的连接没有规则；
  - `/configs` 不报告端口和 TUN：内核进程按名字识别，TUN 网卡取"通往外网的路由所经过的虚拟网卡（Wintun）"。若另有一个 Wintun VPN 承载默认路由，会被误当作内核的 TUN，此时它的连接标 `!`。
- **应用分类：** 用户规则优先；同一来源内，"进程 + 域名" > 只看进程 > 只看域名。内置规则导入自 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)（MIT）。
- **套餐消耗估算：** 只算出口为节点的流量。每个节点的流量乘以倍率，倍率可以在 `config.json` 里手工配置，或从节点名中的 `2x`、`x3`、`0.5x`、`2倍` 之类标记识别，都没有时按 1 倍计算。有出口未知或歧义的流量时给出区间：下限只算已知节点，上限把这部分按出现过的最大倍率全算上。
- **入口判定的顺序：** 本地地址在 TUN 网段内就是 `tun`；路由指向 TUN 但本地地址不在 TUN 网段，说明程序把 socket 绑到了别的网卡，记为 `bypass`；其余再看路由。
- **出口关联的歧义：** 同一源端口、同一进程在时间窗口内匹配到多条内核记录时，如果它们的出口一致（常见于同一连接的日志行和快照），正常记账；不一致就标为 `ambiguous`，账本里单独存放，不计入任何已知节点。
- **覆盖记录：** 采集进程按分钟记下自己运行了多久、其间代理内核在不在、Mihomo 连接流是否连着、ETW 和自身队列各丢了多少事件。`report` 末尾据此列出这段时间没覆盖到的部分。

## 可信边界

每个数字属于下面一层，可信程度依次降低：

| 层 | 内容 | 依据 | 已验证 / 已知误差 |
|---|---|---|---|
| 测量 | 每个 socket 收发的字节数，归属的进程 | ETW Kernel-Network 事件，进程号取事件里的 `PID` 字段 | 定长解码与 TDH 逐字段对照 103,671 个字段无差异；20 MB 下载与 Mihomo 计数差约 1 KB；字节数含 TLS 和 HTTP 开销 |
| 判定 | 入口 | 连接第一个事件时的本地地址、监听表、路由 | 6+6 个录制场景全部符合预期；连接建立后的路由变化不追踪 |
| 关联 | 出口 | 源端口 + 进程名 + 5 秒窗口 | 每条连接标明关联方式；`?` 和 `~` 在报表中单列占比，不计入已知节点 |
| 推断 | 绕过原因 | 见[排障](#排障为什么没走代理) | 只给候选原因和依据；`likely` 取决于程序内部行为 |
| 估算 | 套餐消耗 | 节点流量 × 倍率 | 给出下限和上限；不含代理协议本身的开销（`replay` 列出内核到外部的总字节供对账）；倍率来自配置或节点名，与机场实际计费方式可能不同 |
| 覆盖 | 漏掉了什么 | 按分钟的覆盖记录 | 采集进程没运行、Mihomo 连接断开、丢事件的时段都会列出；有缺口时字节数是下限 |

**看不到的：** 采集进程启动前就存在的连接的早期字节（`trace` 先挂起命令，不受影响）；WSL2 和虚拟机内部的具体程序；程序的命令行参数和私有配置（只能从结果推断）；浏览器开启 DoH 时直连流量的域名。

## 架构与权限

```
netwhered.exe（管理员权限，登录时由计划任务启动，无窗口）
  ETW → 记账引擎 → %ProgramData%\netwhere\ledger.db（每 10 秒写一次）
  Clash API（Mihomo / sing-box）/connections + /logs（WebSocket，断线自动重连）
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
| `diagnose` | 全后端 | 绕过原因：规则、依据和确定程度；`NO_PROXY`、系统代理例外、git 配置的解析 |
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

**内置规则：** 仓库里的 `rules/builtin.txt` 是用 v2fly/domain-list-community@777d056（2026-11-13）生成的，包含 52 个应用、8,967 条域名规则。[rules/apps.txt](rules/apps.txt) 决定哪些列表算作应用，以及应用的显示名。各列表之间会相互包含（例如 google 包含 youtube），同一条规则重复出现时，归给条目更少、也就更具体的那个应用。`netwhere install` 会把这份规则一起装进去。更新规则：

```powershell
git clone --depth 1 https://github.com/v2fly/domain-list-community $env:TEMP\dlc
moon run cmd/rules-import -- $env:TEMP\dlc\data --apps rules\apps.txt --out rules\builtin.txt --source "v2fly/domain-list-community@<commit>"
```

## 状态

**已完成且已测试**（CI 自动测试，或在作者机器上用普通权限实测过）：

- 地址规范化、事件规范化、录制格式、记账引擎（合成场景覆盖系统代理、TUN、IPv6 绕过、短连接日志兜底、端口复用、不一致标记）、增量写库。
- Mihomo 的快照、日志和配置解码；WebSocket 订阅。
- 规则匹配、v2fly 格式解析、规则导入；内置规则来自真实的 v2fly 数据集，有测试检查常见域名的分类结果。
- SQLite 账本：含保活连接；"采集进程停止后只读用户仍能读取"已实测。
- 信箱协议（完整状态机），以及普通权限下的端到端流程。
- 所有命令行命令、降级 trace、路由与监听表查询。
- 普通权限下的录制：DNS-Client 和 Mihomo。

**已在提权实机上验证**（2026-11-13，FlClash / Mihomo）：

- 系统代理模式和 TUN（fake-ip）模式各 6 个场景，全部符合预期，包括"IPv6 绕过 TUN"。录制已脱敏，放在 `testdata/scenarios/`，由 `moon test` 回放。
- 定长解码和 TDH 逐字段对照：103,671 个字段，没有任何差异。没有丢失事件，现在默认使用定长解码。

- `install`：计划任务、目录权限和隐藏控制台窗口都已核实；在已安装的采集进程上实际跑了 `trace`。覆盖安装正在运行的采集进程也没问题。
- `uninstall`：计划任务、采集进程和 ETW 会话都会清掉，数据保留。

- 常驻开销（已安装的采集进程，2 小时，每分钟采样一次，`scripts/sample_overhead.py`）：
  - 私有内存 6.6–8.6 MB，工作集 7–16 MB；
  - CPU 平均 0.52% 单核，单分钟最高 1.2%；
  - ETW 回调平均每个事件约 850 ns；
  - 共 31 万个事件，丢事件和队列丢弃都是 0。

- 发布：`shop1111/netwhere@0.1.0` 已发布到 [Mooncakes](https://mooncakes.io/docs/shop1111/netwhere)，全新消费工程 `moon add` 后调用 `netaddr`、`rules` 通过（2026-11-13）。
- 发布：`shop1111/netwhere@0.2.0` 已发布到 Mooncakes，全新消费工程 `moon add` 后调用 `diagnose`、`netaddr` 通过（2026-11-18）。

**0.2.0 新增**（CI 自动测试）：

- 绕过原因诊断（`diagnose` 包，9 类原因加"未判定"），接入 `trace` 和 `verify`；两份真实录制的诊断结果有快照断言。
- 出口关联方式（快照 / 日志 / 歧义 / 未匹配），歧义出口在账本中单独存放。
- 入口判定先看本地地址，识别绑定了物理网卡的 socket。
- 按分钟的覆盖记录（采集进程运行时间、Mihomo 连接状态、丢事件），`report` 和 `trace` 据此列出缺口；套餐估算给出区间。
- 账本 schema 升到 2，旧账本原地升级（有测试）。
- 录制脚本新增 `nslookup-udp`、`curl-bound-physical` 两个场景，2026-11-18 在提权实机上重新录制了两种模式（终端设了 `HTTPS_PROXY`），全部符合预期，ETW 丢事件 0、定长解码对照无差异。11-13 那份系统代理录制（终端没设代理变量）改名为 `system-proxy-noenv` 保留。三份录制的诊断结果：

  | 录制 | 场景 | 诊断 |
  |---|---|---|
  | system-proxy-noenv | `git ls-remote`、`curl --noproxy *` | `no-proxy-config` (likely) |
  | system-proxy | `curl --noproxy *` | `undetermined`：终端设了 `HTTPS_PROXY`，看不到 `--noproxy` 参数 |
  | system-proxy | `nslookup example.com 1.1.1.1` | `udp-not-proxied` (certain) |
  | tun | `curl -6 --noproxy *` | `tun-no-ipv6` (certain) |
  | tun | `curl --interface <物理网卡地址>` | `bound-off-tun` (certain)，目的地址是 fake-ip，命令超时 |

**sing-box 出口支持**（2026-11-18）：Clash API 快照解码（`processPath` 取进程名）、多行日志按连接 id 拼接、从日志学习出站标签类型、`/configs` 不报告 TUN 时自动识别 TUN 网卡，均有单元测试。在官方 sing-box 1.14.4（mixed 入站 + http 出站 + 自定义名字的直连出站）上录了 `singbox` 场景：节点出口、直连标签、短连接日志兜底三个场景全部符合预期，录制在 `testdata/scenarios/singbox.*`。

**还没做：** 24 小时连续运行。

**计划中：** 托盘和图形界面。

## 已知限制

- 只支持 Windows。出口信息支持 Mihomo 和 sing-box（Clash API）；Xray、V2Ray 等没有按连接查询接口的内核只能提供入口信息。
- sing-box 的 TUN 模式还没有在实机上录制（自动识别 TUN 网卡的逻辑有单元测试）；降级 `trace` 按进程名过滤内核记录，sing-box 不查进程时看不到。
- 浏览器开启安全 DNS（DoH）时，直连流量只能显示 IP，无法显示域名。
- 降级模式看不到直连流量。普通权限下开启 DNS-Client 会话，要求账号属于 Performance Log Users 组。
- 绕过原因只是候选：netwhere 看不到命令行参数和程序自己的配置。`trace` 的路由依据是命令结束时查到的路由，不是连接建立那一刻的。

## 许可

Apache-2.0。内置分类规则的数据来自 v2fly/domain-list-community（MIT）。
