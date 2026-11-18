# netwhere 项目申报书

**基本信息**

- 项目名称：netwhere：Windows 按程序记录流量走向的工具
- 参赛者：郑培翔　联系方式：wx:zhengpx10086
- GitHub：https://github.com/shop1111/netwhere
- Mooncakes：`shop1111/netwhere`（https://mooncakes.io/docs/shop1111/netwhere）
- 项目性质：原创。

**项目简介**

开着代理时，经常说不清某个程序的流量到底走了哪里：进了代理没有，走的哪个节点，还是直接出去了。现有的 Clash/Mihomo 流量统计工具只能看到进入代理内核的连接，而"为什么没走代理"恰恰发生在内核看不见的那部分。netwhere 用 Windows 的 ETW 事件按程序记下本机全部流量，再用源端口关联 Mihomo 的连接记录。它是一个排障工具，回答三个问题：

1. **流量走了哪：** 每份流量记两层，入口（经代理端口 / 经 TUN / 绕过内核 / 局域网）和出口（哪个节点 / 内核直连）。
2. **为什么没走代理：** 对绕过内核的连接给出候选原因、所依据的事实和确定程度；依据不够时写"未判定"，不猜。
3. **结论有多可信：** 每条连接标明出口是怎么关联上的；按分钟记录哪段时间没采到；套餐估算给上下限。

只观测，不拦截、不抓包。

**适用范围**

- **入口层与内核无关。** 代理端口和 TUN 的识别依据是本机监听表、本地地址和路由，Mihomo、sing-box、Xray 等内核都适用；"某程序绕过了代理"这个结论不依赖任何内核。
- **出口层需要 Mihomo。** 节点、命中规则来自 Mihomo 的 Controller API（只读）。Mihomo 是 Clash Verge Rev、FlClash、Mihomo Party 等主流桌面客户端共用的内核；其他内核只有入口信息。
- **只做 Windows。** ETW 不装驱动、不抓包就能按进程记账，这是本项目选 Windows 的原因；Linux/macOS 需要完全不同的采集方式（eBPF、NetworkExtension），不在本项目范围内。
- 不做：拦截、限速、修改代理规则；抓包、解密、保存 URL。

**使用场景**

1. 排查一条命令为什么没走代理：`netwhere trace -- git push`。命令在自己的终端里运行（继承这个终端的环境变量），输出它整个进程树每个连接的入口、出口、字节数，以及绕过连接的候选原因。
2. 看流量账本：`netwhere report --7d --by node`，列出各程序经节点 / 内核直连 / 绕过内核 / 局域网的流量，按节点倍率估算套餐消耗（给区间），末尾列出这段时间没覆盖到的部分。
3. 整理分类：`netwhere unknown` 按流量列出还没归类的域名和进程，用 `classify` 归到某个应用。内置规则从 v2fly/domain-list-community 导入（52 个应用，8,967 条），用户规则优先。

**绕过原因怎么判断**

netwhere 看得到"绕过了"，看不到程序内部为什么这么决定，所以只给候选原因。每条原因列出依据的事实，并标确定程度：`certain` 由观测事实直接推出；`likely` 与事实相符，但取决于程序内部行为；`undetermined` 没有规则成立，只列事实。

| 原因 | 成立条件 | 确定程度 |
|---|---|---|
| `bound-off-tun` | 路由指向 TUN，但连接的本地地址不在 TUN 网段（程序绑定了物理网卡） | certain |
| `tun-no-ipv6` | TUN 开启，目的地址是 IPv6，TUN 网卡没有全局 IPv6 地址 | certain |
| `route-excluded` | TUN 开启，但到该地址的路由不经 TUN | likely |
| `udp-not-proxied` | 只开系统代理，连接是 UDP（QUIC、DNS） | certain |
| `proxy-not-configured` | TUN、系统代理都关，命令环境里没有代理变量 | certain |
| `no-proxy-match` | 目的地命中 `NO_PROXY` 或系统代理例外列表 | likely |
| `mixed-in-process` | 同一进程的其他连接走了代理端口 | likely |
| `no-proxy-config` | 系统代理开着，但命令环境没有代理变量（git 还查 `http.proxy`） | likely |
| `no-core` | 没有代理内核在运行 | certain |

事实来源全部在普通权限下读取：命令的环境变量、当前用户的系统代理设置（注册表）、git 全局配置、Mihomo `/configs` 与网卡表、`GetBestRoute2`。规则在 `diagnose` 包里，是纯计算代码，每条规则有单元测试。

**案例**（来自仓库里两份真实录制，FlClash，2026-11-13；`moon test` 对诊断结果做快照断言，`netwhere verify` 可复现）

1. *git 没走代理（系统代理模式）。* `git ls-remote https://github.com/git/git HEAD`：
   ```
   git-remote-https.exe  tcp github.com:443  bypass  -  1.2 KB  334.0 KB
   no-proxy-config (likely): the program does not read the Windows system proxy, and no proxy variable told it otherwise
       - system proxy: on
       - HTTP_PROXY, HTTPS_PROXY, ALL_PROXY: not set in the command's environment
       - git http.proxy: not set
   ```
   读法：系统代理开着，但 git 不读 Windows 系统代理，环境变量和 git 配置也都没设代理。处理：设 `HTTPS_PROXY` 或 `git config --global http.proxy`。标 `likely` 是因为"git 不读系统代理"是程序行为，netwhere 无法直接观测。作者最初发现这个问题，就是同一条命令在普通终端走代理、在管理员终端直连被重置——两个终端的环境变量不同。
2. *TUN 开着，IPv6 仍然直连。* `curl -6 --noproxy * https://speed.cloudflare.com/...`：
   ```
   curl.exe  tcp speed.cloudflare.com:443  bypass  -  697 B  4.8 MB
   tun-no-ipv6 (certain): TUN carries only IPv4; IPv6 traffic leaves through the physical adapter
       - destination tcp speed.cloudflare.com:443 ([2606:4700:7::da]) is IPv6
       - the TUN adapter has no global IPv6 address
   ```
   读法：这 4.8 MB 没有经过内核。处理：在客户端里开启 TUN 的 IPv6，或关掉系统 IPv6。同一份录制里，同样的命令加 `-4` 走了 TUN、出口 Node A。
3. *系统代理下的 UDP、绑定物理网卡的 socket。* 已加入录制脚本（`nslookup-udp`、`curl-bound-physical`），对应规则 `udp-not-proxied`、`bound-off-tun` 有单元测试。后者以前会被误记为"经 TUN"：路由表指向 TUN，但程序绑了物理网卡。现在入口判定先看本地地址，这类连接记为绕过。

**歧义、缺失和未知怎么处理**

- **关联歧义。** 出口靠（源端口，进程名，5 秒窗口）关联 Mihomo 记录。窗口内多条记录出口一致时（常见于同一连接的日志行和快照）正常记账；出口不一致时标为 `ambiguous`：表格里显示最近的那条并加 `~`，账本里单独存放，不计入任何已知节点。每条连接都记下关联方式：快照、日志、歧义、未匹配。例：合成测试中同一端口 1 秒和 3 秒时各有一条日志，分别指向 Node A、Node B，结果为 Node A + `~`，这 100 字节计入"出口歧义"。
- **出口未知。** 进了内核但没关联上的流量标 `?`，报表列出它的字节数和占比。进了 TUN、持续 3 秒以上却始终没有内核记录的连接另标 `!`（被内核劫持的 DNS 除外）。
- **事件缺失。** 采集进程按分钟记录：自己运行了多久、其间代理内核在不在、Mihomo 连接流是否连着、ETW 和自身队列各丢了多少事件。`report` 末尾列出缺口，例如：
  ```
  collector ran 2 min 0 s of 3 min 0 s (66.6%); traffic outside that time is not counted
  Mihomo connection stream down for 40 s; traffic entering the core then has exit unknown
  events lost: 3 by ETW, 0 by the collector queue; byte counts are a lower bound
  ```
  （这是单元测试里的输入和实际输出。）`trace` 末尾也会列出这次追踪期间 Mihomo 是否断开、是否丢事件。
- **套餐估算给区间。** 下限只算已知节点 × 倍率；上限再把未知和歧义的流量按出现过的最大倍率全算上。例：已知 1000 B（1 倍）+ 500 B（2 倍），未知 300 B、歧义 200 B，估算为 2000–3000 B。

**可信边界**

| 层 | 内容 | 依据 | 已验证 / 已知误差 |
|---|---|---|---|
| 测量 | 每个 socket 的字节数、所属进程 | ETW Kernel-Network，进程取事件里的 `PID` 字段 | 定长解码与 TDH 逐字段对照 103,671 个字段无差异；20 MB 下载与 Mihomo 计数差约 1 KB；含 TLS、HTTP 开销 |
| 判定 | 入口 | 首个事件时的本地地址、监听表、路由 | 系统代理、TUN 两种模式各 6 个录制场景全部符合预期；建立后的路由变化不追踪 |
| 关联 | 出口 | 源端口 + 进程名 + 5 秒窗口 | 每条连接标关联方式；未知、歧义单列，不计入已知节点 |
| 推断 | 绕过原因 | 上面的规则表 | 只给候选和依据；`likely` 取决于程序内部行为 |
| 估算 | 套餐消耗 | 节点流量 × 倍率 | 给上下限；不含代理协议开销；倍率来自配置或节点名，可能与机场实际计费不同 |
| 覆盖 | 漏掉了什么 | 按分钟的覆盖记录 | 采集进程不在、Mihomo 断开、丢事件的时段都会列出；有缺口时字节数是下限 |

看不到的：采集进程启动前就存在的连接的早期字节（`trace` 先挂起命令再恢复，不受影响）；WSL2 和虚拟机里的具体程序；程序的命令行参数和私有配置；浏览器开 DoH 时直连流量的域名。

**核心实现**

- 采集：ETW 只订阅 Kernel-Network、DNS-Client、Kernel-Process 三类事件。C 回调按事件 id 定长解码放进环形队列，MoonBit 主循环取出记账，每 10 秒写一次 SQLite（用量和覆盖记录）。
- 入口判定：回环端口的监听者是不是代理内核（`GetExtendedTcpTable`），本地地址是否在 TUN 网段，目的地址走哪块网卡（`GetBestRoute2`）。内核在回环和 TUN 网段上的流量是应用流量的镜像，不重复计。
- 出口关联：按（源端口，进程，时间窗口）匹配 Mihomo 的 `/connections` 快照；落在两次快照之间的短连接，用 `/logs` 兜底；记录关联方式。
- 权限：只有后台采集进程提权（登录时由计划任务启动），命令行是普通权限，两边只通过文件交换。账本对用户只读；用户能写的只有请求 JSON 和 `config.json`，提权进程用 MoonBit 代码逐项校验。`trace` 的命令先挂起启动，采集进程核对它的父进程后才恢复。没安装采集进程时降级，只用 DNS-Client 和 Mihomo 数据，并标明看不到直连流量。
- 可单独复用的包：`netaddr`、`ledger`（纯计算的记账引擎）、`diagnose`（绕过原因）、`rules`、`mihomo` 全后端可用；`etw`、`route`、`store` 为 native。

**当前进展与验证**

采集进程和命令行已完成，Windows CI 跑 fmt、check、test，共 106 个测试。在 FlClash（Mihomo）上，系统代理和 TUN 两种模式各录制 6 个场景，全部符合预期，脱敏后放进 `testdata/scenarios/` 由 `moon test` 回放，诊断结果也有快照断言。已安装的采集进程连续运行 2 小时：私有内存 6.6–8.6 MB，CPU 平均 0.52% 单核，31 万个事件零丢失。

本轮（0.2.0）根据初审意见新增：绕过原因诊断、出口关联方式与歧义标记、绑定物理网卡的识别、按分钟的覆盖记录、套餐估算区间；账本 schema 升到 2，旧账本原地升级。0.1.0 已发布到 Mooncakes，全新的消费工程 `moon add` 后调用 `netaddr`、`rules` 通过。

还没做：24 小时连续运行；新增两个场景的提权实机录制。第二步是托盘和 WebView2 界面（报表、明细、待归类、规则），按需启动，关闭后不常驻。

**参考与许可**

- v2fly/domain-list-community（https://github.com/v2fly/domain-list-community ，MIT）：内置分类规则数据，由 `cmd/rules-import` 从 commit 777d056 生成。
- 依据 Microsoft ETW / TDH / IP Helper 文档和 Mihomo Controller API（只读 `/connections`、`/logs`、`/configs`）。
- 依赖 `moonbitlang/async`、`moonbit-community/sqlite3`。本项目 Apache-2.0。
