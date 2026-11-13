# netwhere 项目申报书

**基本信息**

- 项目名称：netwhere：Windows 按程序记录流量走向的工具
- 参赛者：郑培翔　联系方式：wx:zhengpx10086
- GitHub：https://github.com/shop1111/netwhere
- Mooncakes：`shop1111/netwhere@0.1.0`（https://mooncakes.io/docs/shop1111/netwhere）
- 参赛方向：新生态项目建设；项目方向：系统工具 / 网络可观测性
- 项目性质：原创。功能形态参照 Proxifier、GlassWire；记账规则来自我此前写的 Go 版 MihomoTracker（私有仓库），用 MoonBit 重写，不复用代码

**项目简介**

开着代理时，经常说不清某个程序的流量到底走了哪里：进了代理没有，走的哪个节点，还是直接出去了。现有的 Clash/Mihomo 流量统计工具（Go、Rust 都有几个）只能看到进入代理内核的连接，而“为什么没走代理”恰恰发生在内核看不见的那部分。netwhere 用 Windows 的 ETW 事件按程序记下本机全部流量，再用源端口关联 Mihomo 的连接记录，每份流量记两层：入口（经代理端口 / 经 TUN / 绕过内核 / 局域网）和出口（哪个节点 / 内核直连）。只观测，不拦截、不抓包。

2026-11-12 检索 Mooncakes 全量索引（3739 个模块），没有 ETW、Mihomo 或流量统计相关的包。

**使用场景**

1. 排查一条命令为什么没走代理：`netwhere trace -- git push`。命令在自己的终端里运行，输出它整个进程树每个连接的入口、出口和字节数。实测例子：同一条 `git ls-remote`，普通终端里走代理，管理员终端里因为环境变量不同变成直连，被远端重置。
2. 看流量账本：`netwhere report --7d --by node`，列出各程序经节点 / 内核直连 / 绕过内核 / 局域网的流量，按节点倍率估算套餐消耗，可以展开到域名。实测例子：开 TUN 后，支持 IPv6 的网站经 IPv6 默认路由出去，完全绕过内核，在账本里显示为 bypass。
3. 整理分类：`netwhere unknown` 按流量列出还没归类的域名和进程，用 `classify` 归到某个应用。内置规则从 v2fly/domain-list-community 导入（52 个应用，8,967 条），用户规则优先。

**核心功能与边界**

- 采集：ETW 只订阅 Kernel-Network、DNS-Client、Kernel-Process 三类事件。C 回调按事件 id 定长解码放进环形队列，MoonBit 主循环取出记账，每 10 秒写一次 SQLite。
- 入口判定：回环端口的监听者是不是代理内核（`GetExtendedTcpTable`），目的地址走哪块网卡（`GetBestRoute2`）。内核在回环和 TUN 网段上的流量是应用流量的镜像，不重复计。
- 出口关联：按（源端口，进程，时间窗口）匹配 Mihomo 的 `/connections` 快照；落在两次快照之间的短连接，用 `/logs` 兜底。
- 权限：只有后台采集进程提权（登录时由计划任务启动），命令行是普通权限，两边只通过文件交换。账本对用户只读；用户能写的只有请求 JSON 和 `config.json`，提权进程用 MoonBit 代码逐项校验。`trace` 的命令先挂起启动，采集进程核对它的父进程后才恢复，所以第一个字节也不会漏。没安装采集进程时降级，只用 DNS-Client 和 Mihomo 数据，并标明看不到直连流量。
- 可单独复用的包：`netaddr`、`ledger`（纯计算的记账引擎）、`rules`、`mihomo` 全后端可用；`etw`、`route`、`store` 为 native。
- 明确不做：拦截、限速、改代理规则；抓包、保存 URL、TLS 解密；Linux 和 macOS；Mihomo 以外内核的出口信息（其他内核只有入口）。浏览器开安全 DNS（DoH）时，直连流量只能显示 IP。

**当前进展与验证**

第一步（采集进程 + 命令行）代码已完成，20 多个提交，Windows CI 跑 fmt、check、test。在 FlClash（Mihomo）上，系统代理和 TUN 两种模式各录制 6 个场景，全部符合预期，脱敏后放进 `testdata/scenarios/` 由 `moon test` 回放。定长解码和 TDH 逐字段对照 103,671 个字段，没有差异；20 MB 下载与内核计数相差约 1 KB。已安装的采集进程连续运行 2 小时：私有内存 6.6–8.6 MB，CPU 平均 0.52% 单核，31 万个事件零丢失；原 Go 版不开窗口私有内存也约 237 MB。

0.1.0 已发布到 Mooncakes，全新的消费工程 `moon add` 后调用 `netaddr`、`rules` 通过。还没做：24 小时连续运行。第二步是托盘和 WebView2 界面（报表、明细、待归类、规则），按需启动，关闭后不常驻。

**参考与许可**

- v2fly/domain-list-community（https://github.com/v2fly/domain-list-community ，MIT）：内置分类规则数据，由 `cmd/rules-import` 从 commit 777d056 生成。
- 依据 Microsoft ETW / TDH / IP Helper 文档和 Mihomo Controller API（只读 `/connections`、`/logs`、`/configs`）。
- 依赖 `moonbitlang/async`、`moonbit-community/sqlite3`。本项目 Apache-2.0。
