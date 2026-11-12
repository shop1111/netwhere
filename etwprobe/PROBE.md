# etwprobe 可行性探针报告（M0）

**问题**：MoonBit native 能否实时读取 ETW 的网络、DNS、进程事件，并据此回答"某条命令的流量走了代理还是直连"？

**结论**：可以。主要结论如下：

- 在管理员权限下，三类事件都能实时读取。
- 场景追踪在真实命令上可用：git 的 4 层进程树、PowerShell 走代理、curl 直连都识别正确。
- 字节数准确：和实际下载量相差 0.3% 以内；和 Mihomo 的计数相比，同一条连接只差约 1.4 KB。
- ETW 记录的本地端口和 Mihomo 连接的 `sourcePort` 能一一对上，可以据此补上域名、节点和命中规则。

**必须接受的限制**：Kernel-Network 和 Kernel-Process **需要管理员权限**。

- 日期：2026-11-13
- 机器：Windows 11 Home China 10.0.26200，x64，系统语言 zh-CN；网络是 WLAN 双栈
- 代理：FlClash（Mihomo 内核），混合端口 7890，Controller 127.0.0.1:9090。测了两种模式：**系统代理模式**，以及 **TUN 模式**（fake-ip，stack: Mixed）。TUN 的结果见文末专节。
- 工具链：moon 0.1.20261104，moonc v0.10.20+65efd5b93，C 后端，MSVC
- 产物：`probe.exe` release 版 313 KB，debug 版 416 KB

## 怎么跑

```powershell
moon build --target native --release
# 不提权：只看权限情况
_build\native\release\build\cmd\probe\probe.exe env
# 提权后跑全部实验（会弹 UAC），原始输出写到 evidence\raw\（已加入 git 忽略）
Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File scripts\run_admin.ps1'
Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File scripts\run_admin_proxy.ps1'
python -I scripts\sanitize.py evidence\raw evidence   # 脱敏后复制到 evidence\
```

| 模式 | 作用 |
|---|---|
| `env` | 检查令牌是否提权；分别开启三个 provider |
| `leak` / `check` | 开启会话后不停止就退出；检查残留会话以及清理逻辑 |
| `schema [秒]` | 打印每种（provider, 事件 id, 版本）的第一条事件，包括所有字段 |
| `net [秒] [代理端口]` | 全机按进程和端点汇总字节数 |
| `trace [--proxy-port N] -- <命令>` | 运行命令，跟踪它的整个进程树，按目的地和走向汇总流量 |

实现结构：

- [etw/etw_stub.c](etw/etw_stub.c)：`ProcessTrace` 在 C 线程上回调；回调里用 TDH 把事件解码成紧凑的二进制记录，放进加锁的字节队列。MoonBit 每 100–200 ms 从自己的线程取走数据。**MoonBit 运行时从不在 ETW 线程上被调用。**
- [etw/etw.mbt](etw/etw.mbt)：负责 FFI 和记录解码。字段名（schema）只在每种事件第一次出现时传一次，之后的记录按相同顺序只传值。

## 结果总览

| # | 验证项 | 结论 | 证据 |
|---|---|---|---|
| 1 | 不提权（账号属于 Performance Log Users 组） | StartTrace 和 DNS-Client **可以**；Kernel-Network、Kernel-Process 的 EnableTraceEx2 返回 **5（拒绝访问）** | [env.txt](evidence/env.txt) |
| 2 | 提权后三个 provider 都能开启并收到事件 | **通过** | [env-admin.txt](evidence/env-admin.txt)；schema 输出 |
| 3 | 会话会比创建它的进程活得更久；下次启动时清理残留会话 | **确认存在这个问题，清理逻辑通过**（`leak` 之后 logman 能看到会话，`check` 停掉了 1 个残留会话） | [leak.txt](evidence/leak.txt)、[check.txt](evidence/check.txt) |
| 4 | 场景追踪：进程树 | **通过**：`git ls-remote` 追到 4 层进程（Git\cmd\git.exe 包装器 → git.exe → git.exe → git-remote-https.exe）。第一次运行时根进程名显示为"?"，原因是进程退出后才去查名字；之后改为从启动事件取名，第二次运行时已正确显示 | [trace-git-ls-remote.txt](evidence/trace-git-ls-remote.txt) |
| 5 | 场景追踪：走向判断 | **通过**：PowerShell `Invoke-WebRequest` 走代理端口，对端是 FlClashCore；`curl --noproxy` 直连；`curl -x` 走代理端口 | trace-* 文件 |
| 6 | 字节准确度（直连） | 5 MB：ETW 4895.5 KB，实际负载 4882.8 KB（+0.26%，多出的是 TLS/HTTP 开销）；50 MB：+0.15% | [trace-curl-direct-5mb.txt](evidence/trace-curl-direct-5mb.txt) |
| 7 | 和 Mihomo 计数对比（走代理 20 MB） | ETW 记录 curl 回环 socket 收到 19565.8 KB（约 20 035 3xx B）；Mihomo 记录同一连接下载 20 033 955 B，差约 1.4 KB，正好是第二次请求的响应。上传方面 ETW 950 B、Mihomo 794 B，差的 156 B 是 CONNECT 请求头，Mihomo 只计隧道内的数据 | [trace-curl-proxy-20mb.txt](evidence/trace-curl-proxy-20mb.txt)、[proxy-20mb-mihomo.txt](evidence/proxy-20mb-mihomo.txt) |
| 8 | 用端口关联 Mihomo 连接 | **通过**：ETW 的本地端口 64607 对应 Mihomo `sourcePort=64607`，进程同为 curl.exe，并得到 host、节点和规则（Match）。全机 `net` 实验中，与 Mihomo 快照时间上有重叠的 4 个回环连接，端口和进程也全部对上 | 同上 |
| 9 | 开销 | 见下文 | 各文件末尾的 consumer statistics |

## 关键发现（直接影响设计）

1. **必须用事件里的 `PID` 字段，不能用事件头的进程号**。全机 20 秒内 2797 个网络事件中，有 2300 个的事件头 pid 是 System(4)、Idle(0) 或代理内核，而不是真正拥有 socket 的进程。
2. **TCP 和 UDP 的地址含义不同**：
   - TCP 事件不分收发，`daddr/dport` 都是远端，`saddr/sport` 都是本地。
   - UDP 的接收事件是按数据包方向记录的：`daddr` 是本机，`saddr` 才是远端。
   - 记账时必须按"协议 × 方向"分别处理。
3. **系统代理模式下，回环连接两端都会出现**：应用 → 127.0.0.1:7890，以及代理内核 7890 → 应用端口。内核往节点方向的出站流量又是一份，而且混着所有走代理的应用；在本次 20 MB 实验中它比应用侧多 0.37%（协议开销）。**正确做法是只按应用侧的回环 socket 记账，再通过 sourcePort 关联到 Mihomo 拿节点和域名**，不能把内核的流量也算进去。
4. **"走了代理端口"不等于"走了代理"**：例如 lsass.exe 的证书吊销检查（OCSP/CRL）经过 7890，但在 Mihomo 里命中了 DIRECT 链。所以至少要区分五类走向：代理节点 / 经内核直连 / 绕过代理直连 / 局域网 / 回环。
5. **DNS**：
   - 3008 事件的事件头 pid 就是发起查询的进程。
   - v2 版本的 3009/3016/3018/3019/3020 事件由 dnscache 记录，但带有 `ClientPID` 字段。
   - `QueryResults` 的格式是 `type: 5 <CNAME>;<IP>;<IP>;`，需要解析。
   - 走代理时，域名解析发生在代理那边，ETW 看不到 DNS 记录（PowerShell 那条 trace 的 DNS 为 0），域名只能从 Mihomo 拿。
6. **TDH 返回的名称会被本地化**：DNS 和进程事件的 opcode 名称是"信息、开始、停止"，Kernel-Network 是英文。**正式实现要按 provider 和事件 id 识别**，不能依赖名称字符串。探针按名称识别只是为了验证字段。
7. **进程启动事件的 `ImageName` 是设备路径**（`\Device\HarddiskVolume3\...`），需要转换成盘符路径；退出事件里只有短文件名。
8. **一个真实发现，正好是这个工具要解决的问题**：本机的 `HTTP(S)_PROXY` 环境变量没有写在用户或系统环境变量里，只存在于当前会话的进程环境中。所以在提权的 PowerShell 里，curl 和 git 都改成了直连，git 访问 GitHub 被重置（exit 128）；而同一窗口里的 `Invoke-WebRequest` 读的是系统代理，仍然走代理。同一台机器，"在哪个终端里执行"决定了流量走向。

## 开销（release 版，统计口径为 TDH 通用解码）

| 场景 | 事件速率 | 回调耗时 | 探针 CPU | 工作集 |
|---|---|---|---|---|
| 全机空闲 20 s | 144/s | 7.0 µs/事件 | 15 ms | 8.7 MB |
| 直连 50 MB，限速 5 MB/s | 602/s | 3.6 µs/事件 | 109 ms / 24 s（约 0.45% 单核） | 9.0 MB（峰值 23 MB，trace 模式会把事件全部留到最后） |
| 走代理 20 MB，限速 4 MB/s | 416/s | 3.7 µs/事件 | 46 ms / 15 s | 8.9 MB |

- 私有内存 34 MB，主要是预先分配的 32 MB 队列加 4 MB 读取缓冲，实际最大只用到 177 KB，正式版可以降到 1 MB 以内。
- 没有丢失记录，ETW 的 EventsLost 和 BuffersLost 都是 0。
- 每 MB 流量大约产生 100–300 个接收事件。走代理时，应用侧、内核回环侧、内核出站侧各一份。
- **估算**（未实测）：100 Mbps 走代理约 4k–10k 事件/秒；按通用 TDH 解码约占 1.5–3.5% 单核。正式实现应该按事件 id 写固定偏移的解码代码，绕开 TDH，目标是每个事件 1 µs 以内，在 M1 实测。

## TUN 模式补测（同日，FlClash 切到 TUN）

环境（[tun-env.txt](evidence/tun-env.txt)）：

- TUN 网卡 `FlClash`（Meta Tunnel），地址 198.18.0.1/30，DNS 被劫持到 198.18.0.2；
- `stack: Mixed`：TCP 走系统协议栈，UDP 走 gVisor；
- 系统代理已关闭，7890 端口仍在监听；
- **IPv4 默认路由指向 FlClash，但 IPv6 的 `::/0` 只经过 WLAN。**

| # | 验证项 | 结论 | 证据 |
|---|---|---|---|
| T1 | 走 fake-ip 的连接 | 应用连接 `198.18.0.x:443`，可以用 DNS 事件反查出域名（例如 www.github.com → 198.18.0.11） | [tun-trace-curl-github.txt](evidence/tun-trace-curl-github.txt) |
| T2 | 用端口关联 Mihomo | **通过**：ETW 的本地端口 50211 = Mihomo `sourcePort=50211`，`type=Tun`，`sourceIP=198.18.0.1`，进程、host、规则齐全 | [tun-20mb-mihomo.txt](evidence/tun-20mb-mihomo.txt) |
| T3 | 和 Mihomo 计数对比（20 MB） | ETW 记录应用 socket 收到 19566.2 KB（约 20 035 8xx B），Mihomo 记录 20 034 499 B，差约 1.3 KB，是第二次请求的响应；上传 818 B 对 794 B。**和系统代理模式一样精确** | [tun-trace-curl-20mb.txt](evidence/tun-trace-curl-20mb.txt) |
| T4 | 管理员终端里的 `git ls-remote` | **成功**（exit 0，收到 298 KB）。系统代理模式下同样的命令被重置连接；TUN 让流量走向不再取决于终端的环境变量 | [tun-trace-git-ls-remote.txt](evidence/tun-trace-git-ls-remote.txt) |
| T5 | 在 TUN 模式下显式使用 `-x 127.0.0.1:7890` | 仍然走代理端口，对端是 FlClashCore，**两种入口会同时存在** | [tun-trace-curl-proxyport.txt](evidence/tun-trace-curl-proxyport.txt) |
| T6 | **IPv6 绕过 TUN** | `curl https://www.baidu.com` 拿到 A 记录 198.18.0.10（fake-ip）和真实的 AAAA 记录，curl 选了 IPv6，**直接从 WLAN 出去，完全没经过代理内核**。全机观察时，一次 8 MB 的 IPv6 下载也是这样 | [tun-trace-curl-baidu.txt](evidence/tun-trace-curl-baidu.txt) |

TUN 模式带来的设计结论：

1. **代理内核这一侧也会出现一份镜像流量**。在系统协议栈下，内核以 `198.18.0.1:<inboundPort> ↔ 198.18.0.2:10000` 的形式出现，字节数和应用一侧完全对称（全机观察中，claude.exe 的 9494/521 B 对应 FlClashCore 的 521/9494 B）。所以必须排除代理内核进程在回环和 TUN 网段上的流量，否则会重复计数。gVisor 栈（这里是 UDP）没有 socket，不会产生这一侧的事件。
2. **只看目的地址，判断不了是否经过了代理内核**。目的地址是 fake-ip 时肯定进了 TUN；但目的地址是真实 IP 时，可能进了 TUN（IPv4 默认路由），也可能绕过了（IPv6）。正式实现应该用**系统路由表**判断：对目的地址查询 `GetBestRoute2`，看它走哪个网卡，结果可以缓存。这样即使是 Mihomo 快照没抓到的短连接，也能判断有没有进 TUN。是否命中代理节点，仍然要靠 Mihomo 关联。
3. **"开了 TUN 但有流量没进 TUN"本身就是 netwhere 要发现的问题**。T6 是在本机真实配置上发现的：只要网站支持 IPv6，流量就会绕过代理内核。这个例子可以和系统代理模式下的环境变量例子一起放进 README。
4. 即使降级运行，也能拿到不少信息：DNS-Client 不需要管理员权限，"进程 → 域名 → fake-ip"的对应关系仍然可以得到。

## 没有验证的部分

- TUN 的纯 gVisor 栈和 real-ip 模式；sing-box 内核；IPv6 回环；浏览器 DoH。
- 长时间运行时的稳定性，PID 被复用、端口被复用时的关联错误。
- 用 MoonBit 实现 Mihomo 的 WebSocket 客户端。本次快照是用 curl 获取的。
- 非管理员时的降级模式：只用 Mihomo 数据，加上 DNS-Client 事件（这个 provider 不提权也能开）。

## 下一步建议

1. 按事件 id 写固定偏移解码，测每个事件的耗时，确定正式实现的开销底线。
2. 验证用 `GetBestRoute2` 判断走向（TUN 和物理网卡，IPv4 和 IPv6）。
3. 按 [DECISIONS.md](../DECISIONS.md) 重写规划。权限架构已经定了：提权的采集进程加普通权限的客户端。
