# netwhere

**Windows 本机流量走向工具**：按程序记录流量从哪里出去、去了哪个节点、用了多少；没走代理时说明可能的原因。

- 数据来自 ETW（网络、DNS、进程事件），短连接也不漏；只观测，不拦截、不抓包。
- 本机运行 Mihomo 或 sing-box 时，通过 Clash API 补上节点、域名和规则。
- 每个结论标明可信程度（见[可信边界](#可信边界)）。
- 托盘图标和图形界面：今日流量、趋势、按应用 / 域名 / 节点逐级展开、待归类、规则和设置。
- MoonBit（native）编写，C 只用于调用 Windows API；界面是手写的 HTML/CSS/JS，跑在 WebView2 里。

## 使用

```powershell
netwhere install                 # 安装采集进程、托盘和界面（弹一次 UAC），并打开"登录时启动"
netwhere status                  # 采集进程、代理内核、运行模式
netwhere start | stop            # 启动 / 停止采集（不弹 UAC）
netwhere pause | resume          # 暂停 / 恢复记账，采集进程保持运行
netwhere autostart on | off      # 登录时启动托盘（托盘再启动采集）
netwhere trace -- git push       # 在当前终端运行命令，报告其进程树的流量走向
netwhere report --7d --by node   # 按节点汇总，估算套餐消耗
netwhere unknown                 # 未归类的流量；用 classify 归类
netwhere export --csv --30d --out usage.csv
netwhere uninstall [--purge]
```

`trace` 示例（`testdata/scenarios/tun` 录制，TUN 模式下 `curl -6 --noproxy *`）：

```
process   destination                   entry   exit  up     down    conns  rule
curl.exe  tcp speed.cloudflare.com:443  bypass  -     697 B  4.8 MB  1

why it bypassed the core (candidate causes; "likely" depends on what the program does internally):
  tun-no-ipv6 (certain): TUN carries only IPv4; IPv6 traffic leaves through the physical adapter
      - destination tcp speed.cloudflare.com:443 ([2606:4700:7::da]) is IPv6
      - the TUN adapter has no global IPv6 address
```

出口列标记：`?` 进了内核但没关联到记录；`~` 多条记录出口不一致；`!` 进了 TUN 却没有内核记录。

**托盘和界面**：托盘显示今日流量和采集状态，菜单里可以打开界面、暂停或恢复、切换"登录时启动"、退出。像普通应用一样：打开托盘就开始采集，从托盘退出就停止采集；"登录时启动"关掉后，登录时什么都不运行。界面窗口只在打开时运行，关掉后连同 WebView2 进程一起退出。

| 页面 | 内容 |
|---|---|
| 概览 | 总流量、套餐估算区间、五类走向（经节点 / 内核直连 / 出口未知 / 绕过 / 局域网）、趋势图、应用排行、覆盖缺口 |
| 明细 | 按应用、域名、进程、节点、入口分组，点一行继续细分 |
| 节点与套餐 | 各节点流量、倍率（可改）、套餐消耗 |
| 待归类 | 未归类的进程和域名，一键归类为规则 |
| 规则 / 设置 | 用户规则；采集状态与启停、登录时启动、Clash API 地址和密钥、保留天数、导出 CSV |

界面和命令行用同一套查询代码（`query` 包），数字一致。

## 统计口径

| 层 | 取值 | 依据 |
|---|---|---|
| 入口 | `proxy-port` / `tun` / `bypass`（有内核但直连）/ `direct`（没有内核）/ `lan` | 回环端口的监听者；本地地址是否在 TUN 网段；`GetBestRoute2` |
| 出口 | 节点 / `DIRECT` / `REJECT` / `?` / `~` | 按（源端口，进程，5 秒窗口）关联内核快照，短连接用 `/logs` 兜底 |

- 只记应用一侧的 socket；内核在回环和 TUN 上的流量是镜像，不重复计。字节数含 TLS 和 HTTP 开销。
- 域名：内核报告的 host > 本进程 DNS 应答 > 全机 DNS 应答。
- 歧义：多条记录出口一致时正常记账，不一致时标 `~`，不计入任何已知节点。
- 套餐估算：节点流量 × 倍率（`config.json` 或节点名里的 `2x` 等）；有 `?`/`~` 流量时给出上下限。
- 覆盖：按分钟记录采集进程是否在运行、内核连接是否断开、是否丢事件；`report` 末尾列出缺口。
- sing-box：默认不报告进程，只靠源端口和时间窗口关联；多行日志按连接 id 拼接，并从日志学到每个出站标签的类型；`/configs` 不报告 TUN，TUN 网卡取承载外网路由的 Wintun 网卡。

## 为什么没走代理

只给候选原因，并列出依据和确定程度：`certain` 由事实直接推出；`likely` 取决于程序内部行为；`undetermined` 只列事实。

| 原因 | 条件 | 程度 |
|---|---|---|
| `bound-off-tun` | 路由指向 TUN，但本地地址不在 TUN 网段 | certain |
| `tun-no-ipv6` | TUN 开启，目的是 IPv6，TUN 无 IPv6 地址 | certain |
| `route-excluded` | TUN 开启，但路由不经 TUN | likely |
| `udp-not-proxied` | 只开系统代理，连接是 UDP | certain |
| `proxy-not-configured` | TUN、系统代理、代理变量都没有 | certain |
| `no-proxy-match` | 命中 `NO_PROXY` 或系统代理例外 | likely |
| `mixed-in-process` | 同进程其他连接走了代理 | likely |
| `no-proxy-config` | 开着系统代理，但程序环境里没有代理变量 | likely |
| `no-core` | 没有代理内核 | certain |

依据都在普通权限下读取：命令的环境变量、系统代理设置、git 配置、内核 `/configs` 与网卡表、路由。看不到命令行参数和程序自己的配置。

## 可信边界

| 层 | 内容 | 已验证 / 已知误差 |
|---|---|---|
| 测量 | socket 字节数、进程 | TDH 逐字段对照 103,671 个字段无差异；20 MB 下载与内核计数差约 1 KB |
| 判定 | 入口 | 4 份录制、24 个场景全部符合预期；连接建立后的路由变化不追踪 |
| 关联 | 出口 | 每条连接标关联方式（快照 / 日志 / 歧义 / 未匹配）；`?`、`~` 单列 |
| 推断 | 绕过原因 | 只给候选和依据 |
| 估算 | 套餐消耗 | 给上下限；不含代理协议开销；倍率可能与机场计费不同 |
| 覆盖 | 缺口 | 有缺口时字节数是下限 |

看不到：采集进程启动前已有连接的早期字节（`trace` 不受影响）；WSL2 和虚拟机里的具体程序；DoH 下直连流量的域名。

## 架构

```
netwhered.exe（管理员，按需运行的计划任务）
  ETW → 记账引擎 → %ProgramData%\netwhere\ledger.db（每 10 秒）
  Clash API /connections + /logs（WebSocket）
        ▲ 读 ledger.db          │ 写 requests\*.json（trace / 暂停 / 恢复 / 停止）、config.json
netwhere.exe       命令行（普通权限）
netwhere-tray.exe  托盘（普通权限，常驻；HKCU\...\Run 里的"登录时启动"）
netwhere-ui.exe    界面（普通权限，打开时才运行；页面走 netwhere:// 自定义协议，不开端口）
```

只有采集进程提权；用户能写的只有请求 JSON 和 `config.json`，由 MoonBit 代码逐项校验；账本对用户只读。计划任务属于安装用户、不带触发器，所以普通权限的 `schtasks /Run` 就能启动它，不弹 UAC；"登录时启动"是托盘在 HKCU 下的 Run 值，开关也不用提权。停止走信箱请求，采集进程自己退出并清理 ETW 会话（返回 0，任务不会重启）。`trace` 的命令先挂起启动，采集进程确认后才恢复。没装采集进程时降级，只用 DNS 和内核数据。

## 包

| 包 | 后端 | 内容 |
|---|---|---|
| `netaddr`、`ledger`、`mihomo`、`rules`、`diagnose` | 全后端 | 地址规范化；记账引擎与回放；Clash API 解码（Mihomo、sing-box）；分类规则；绕过诊断 |
| `mailbox`、`config`、`report`、`installer`、`scenario` | 全后端 | 信箱协议、配置、输出、安装计划、场景校验 |
| `etw`、`route`、`sys`、`store`、`mihomo/client` | native | ETW、IP Helper、进程、SQLite、WebSocket |
| `control`、`query` | native | 采集进程的启停与状态、自启开关、配置读写；报表聚合（命令行和界面共用） |

安装后开始菜单里有 netwhere：托盘没在运行时打开它会启动托盘、开始采集并打开窗口；托盘在运行时打开它只打开窗口。登录时自启只出现托盘图标。界面的运行记录在 `%LOCALAPPDATA%\netwhere\ui.log`。

托盘和界面在 workspace 里的另一个模块 `gui/`（`shop1111/netwhere-gui`，不发布），依赖 [`justjavac/tray`](https://mooncakes.io/docs/justjavac/tray) 和 [`Nanaloveyuki/moonview`](https://mooncakes.io/docs/Nanaloveyuki/moonview)；发布到 Mooncakes 的库本身不带这些依赖。

Mooncakes：[`shop1111/netwhere`](https://mooncakes.io/docs/shop1111/netwhere)。

## 开发

```powershell
moon test --target native
moon build --target native --release
```

需要 moonc ≥ 0.10.20 和 MSVC；构建界面还需要 Node.js（moonview 的 prebuild 从 nuget.org 下载并校验 WebView2 SDK），并且 PATH 里 Windows 自带的 `tar.exe` 要排在 Git 的 tar 前面。

改了 `gui/netwhere-ui/web/` 下的页面后运行 `python -I scripts\embed_web.py` 重新内嵌；调试时 `netwhere-ui.exe --web gui\netwhere-ui\web` 直接读这个目录，不用重新编译。

录制回放样例（每次弹一次 UAC，命令在当前终端环境里运行）：

```powershell
.\scripts\record-scenarios.ps1 -Mode system-proxy   # 或 tun；sing-box 用 -Mode singbox -Controller -ProxyPort
netwhere verify testdata\raw\tun.manifest.json
python -I scripts\sanitize_recording.py testdata\raw\tun.manifest.json testdata\scenarios
```

内置规则由 `cmd/rules-import` 从 v2fly/domain-list-community@777d056 生成（52 个应用、8,967 条）。

## 状态

- CI 跑 fmt、check、test（120 个测试），并检查内嵌页面是否最新。
- 实机录制（脱敏后在 `testdata/scenarios/`，`moon test` 回放）：FlClash 系统代理两份、TUN 一份，sing-box 1.14.4 代理端口一份，ETW 丢事件均为 0。
- 常驻开销（2 小时）：私有内存 6.6–8.6 MB，CPU 平均 0.52% 单核，31 万事件零丢失。
- 托盘常驻私有内存约 2 MB；界面打开时整组进程（窗口加 WebView2）私有内存约 170 MB，关闭后 0.2 秒内全部退出。
- 还没做：24 小时连续运行、sing-box TUN 模式实录。

## 已知限制

- 只支持 Windows；Xray、V2Ray 只有入口信息。
- 另一个 Wintun VPN 承载默认路由时，可能被当成 sing-box 的 TUN。
- 降级 `trace` 按进程名筛选内核记录，sing-box 不查进程时看不到。
- 降级模式看不到直连流量。

## 许可

Apache-2.0。内置规则数据来自 v2fly/domain-list-community（MIT）。
