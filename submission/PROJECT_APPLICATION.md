# netwhere 项目申报书

- 项目：netwhere：Windows 按程序记录流量走向的工具（原创）
- 参赛者：郑培翔　联系方式：wx:zhengpx10086
- GitHub：https://github.com/shop1111/netwhere　Mooncakes：`shop1111/netwhere@0.4.0`

**简介**：开着代理时，常说不清某个程序的流量进没进代理、走了哪个节点。现有 Clash 流量工具只看得到进入内核的连接，而"为什么没走代理"恰恰发生在内核看不见的地方。netwhere 用 ETW 按程序记下本机全部流量（只观测，不拦截、不抓包），再用源端口关联代理内核的连接记录，回答三个问题：流量走了哪（入口：代理端口 / TUN / 绕过 / 局域网；出口：节点 / 直连），为什么没走代理（候选原因与依据），结论有多可信。常用命令：`netwhere trace -- git push`（追踪一条命令）、`netwhere report --7d --by node`（流量账本与套餐估算）；也可以用托盘图标和图形界面查看。

**适用范围**：入口层只依据本机监听表、本地地址和路由，与内核无关；出口层支持实现了 Clash API 的 Mihomo（Clash Verge Rev、FlClash 等）和 sing-box，Xray、V2Ray 只有入口信息；只做 Windows，因为 ETW 不装驱动就能按进程记账。

**绕过原因怎么判断**：netwhere 看得到"绕过了"，看不到程序内部的决定，所以只给候选原因并标确定程度：`certain` 由事实直接推出，`likely` 取决于程序行为，都不成立时为 `undetermined`，只列事实。

| 原因 | 条件 | 程度 |
|---|---|---|
| `bound-off-tun` / `tun-no-ipv6` | 路由指向 TUN 但本地地址不在 TUN 网段 / 目的是 IPv6 而 TUN 无 IPv6 | certain |
| `udp-not-proxied` / `proxy-not-configured` / `no-core` | 只开系统代理时的 UDP / 没有任何代理设置 / 没有内核 | certain |
| `route-excluded` / `no-proxy-match` | 路由不经 TUN / 命中 `NO_PROXY` 或系统代理例外 | likely |
| `no-proxy-config` / `mixed-in-process` | 开着系统代理但程序环境无代理变量 / 同进程其他连接走了代理 | likely |

依据都在普通权限下读取：命令的环境变量、系统代理设置、git 配置、内核 `/configs`、网卡表与路由。规则在 `diagnose` 包，逐条有单元测试。

**案例**（仓库内真实录制，`netwhere verify` 可复现，`moon test` 有快照断言）
```
git ls-remote（系统代理模式）
git-remote-https.exe  tcp github.com:443  bypass  -  1.2 KB  334.0 KB
no-proxy-config (likely): the program does not read the Windows system proxy, and no proxy variable told it otherwise
    - system proxy: on;  HTTP_PROXY, HTTPS_PROXY, ALL_PROXY: not set;  git http.proxy: not set

curl -6 --noproxy *（TUN 模式）
curl.exe  tcp speed.cloudflare.com:443  bypass  -  697 B  4.8 MB
tun-no-ipv6 (certain): TUN carries only IPv4; IPv6 traffic leaves through the physical adapter
```

- git 不读 Windows 系统代理，处理是设 `HTTPS_PROXY` 或 `http.proxy`；标 `likely` 是因为这是程序行为，无法直接观测。
- `curl --interface <物理网卡>` 在 TUN 下超时 → `bound-off-tun`：fake-ip 地址 198.18.0.15 只有内核能应答。这类连接以前会被误记为"经 TUN"。
- `nslookup example.com 1.1.1.1` 在系统代理模式下 → `udp-not-proxied`。
- 终端设了 `HTTPS_PROXY`，`curl --noproxy *` 仍直连 → `undetermined`：真正原因是命令行参数，netwhere 看不到，就不下结论。

**歧义、缺失和未知**
- 关联歧义：窗口内多条内核记录出口不一致时标 `~`，单独存放，不计入任何已知节点。
- 出口未知：进了内核但没关联上标 `?`，报表单列占比；进了 TUN 却始终没有内核记录的标 `!`。
- 事件缺失：按分钟记录采集进程是否运行、内核连接是否断开、是否丢事件，`report`/`trace` 末尾列出缺口；有缺口时字节数是下限。
- 套餐估算：下限只算已知节点 × 倍率，上限把 `?`、`~` 流量按最大倍率计入。

**可信边界**

| 层 | 已验证 / 已知误差 |
|---|---|
| 测量（字节数、进程） | TDH 逐字段对照 103,671 个字段无差异；20 MB 下载与内核计数差约 1 KB |
| 判定（入口） | 4 份录制、24 个场景全部符合预期；连接建立后的路由变化不追踪 |
| 关联（出口） | 每条连接标关联方式；sing-box 默认不报告进程，只靠源端口和时间窗口 |
| 推断 / 估算 | 只给候选原因；套餐给上下限，不含代理协议开销 |

看不到：采集进程启动前已有连接的早期字节、WSL2 和虚拟机里的具体程序、命令行参数、DoH 下直连流量的域名。

**实现与进展**
- ETW 回调定长解码进环形队列，MoonBit 记账写 SQLite；只有后台采集进程提权，命令行普通权限，两边只通过文件交换。
- 托盘和图形界面（第二步）：托盘显示今日流量和采集状态，可暂停、恢复、切换登录时启动、退出；界面有概览（走向占比、趋势、应用排行、覆盖缺口）、逐级展开的明细、节点倍率与套餐、待归类一键归类、规则和设置。界面是手写的 HTML/CSS/JS，经 `Nanaloveyuki/moonview` 跑在 WebView2 里，页面走自定义协议不开端口；托盘用 `justjavac/tray`。界面与命令行共用 `query` 包，数字一致。
- 像普通应用一样可控：采集任务改为按需运行，普通权限即可启动，不弹 UAC；登录时启动由托盘的 HKCU Run 值开关；从托盘退出经信箱让采集进程自己退出并清理 ETW 会话。托盘常驻约 2 MB；界面只在打开时运行（约 170 MB，主要是 WebView2），关闭后 0.2 秒内全部退出。
- CI 共 120 个测试；实机录制 FlClash 三份、sing-box 1.14.4 一份，ETW 丢事件均为 0；采集进程 2 小时私有内存 6.6–8.6 MB、CPU 0.52% 单核。
- 本轮根据初审意见新增绕过诊断、关联方式、覆盖记录、套餐区间（0.2.0）、sing-box 出口（0.3.0）和托盘与图形界面（0.4.0），已发布到 Mooncakes。
- 还没做：24 小时连续运行、sing-box TUN 模式实录。

**参考与许可**：v2fly/domain-list-community（MIT）；Microsoft ETW / IP Helper 文档；Mihomo 与 sing-box 的 Clash API。依赖 `moonbitlang/async`、`moonbit-community/sqlite3`；托盘和界面另用 `justjavac/tray`、`Nanaloveyuki/moonview`。Apache-2.0。
