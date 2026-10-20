# WalletGuard

只读自检：检查 AI Agent Harness 的**中转站（relay）/ 中间人注入风险**。
不读密钥、不传数据、不修改任何配置——只写一份报告。

A read-only self-check for agent harnesses: is your model traffic going through a
third-party relay, can injected tool calls execute, and how much can they move?

---

## 它检查什么

| 节 | 检查项 | 想回答的问题 |
|---|---|---|
| 0 | 选择 harness | 你装了哪些 agent，先选再查 |
| 1 | 模型链路：`baseURL` 域名、环境变量改道 | 模型流量是否经过第三方中转 |
| 2 | 钱包链路：`WALLET_API_URL`、代理、自定义 CA、`NODE_TLS_REJECT_UNAUTHORIZED`、hosts、DNS、TLS 签发者 | 出网链路能否被本机程序观察/改写 |
| 3 | 注入闸门：`approval` / `sandbox`（含跨会话一致性） | 伪造的工具调用会不会被执行 |
| 4 | 损失上限：钱包状态、今日剩余额度、devMode、代币白名单 | 一旦执行，能被转走多少钱 |

TLS 签发者检查是本工具的核心：它直接与目标站点握手，读证书链的
Issuer。如果签发者不是公共 CA，说明存在 TLS 中间人。

## 支持的环境

| 系统 | 启动方式 | 依赖 |
|---|---|---|
| Windows | 双击 `WalletGuard.cmd` | 系统自带 PowerShell 5.1+ |
| macOS | 双击 `WalletGuard.command` | PowerShell 7（`brew install --cask powershell`） |

## 支持的 harness

`dsh`（DeepSeek Harness）、`codex`、`claude`、`gemini`、`qwen`、`opencode`、`cursor`

没有指定时，脚本会探测本机已安装的 harness 并让你选。

```powershell
./WalletGuard.ps1                 # 弹菜单
./WalletGuard.ps1 -Harness dsh    # 只查一个
./WalletGuard.ps1 -Harness all    # 全查
./WalletGuard.ps1 -Unicode        # 用制表符边框
```

DeepSeek Harness 的审批策略从会话记录读取；其它 harness 从配置文件里
匹配 `approval_policy` / `defaultMode` / `sandbox_mode` 等键。

## 它会连接什么

- `www.binance.com:443`：TLS 握手读证书签发者（不发送任何数据）
- DNS 解析 `www.binance.com`
- 若装了 `baw`：调用 `wallet status --json` / `wallet settings --json`（只读接口）

除此之外**没有任何出网行为**，报告只写到本地桌面。

## 它不会做什么

- 不读取、不打印、不上传任何 cookie / 会话 / API key
- 不修改任何配置
- 不执行任何钱包写操作（转账、swap、下单）
- 不安装任何东西

唯一副作用：`baw` 子进程首次运行可能创建 `~/.baw/session.json`（clientId）。

## 已知限制

- 这是**姿势快照**，不是攻击检测：它说明"路通不通、后果多大"，不说明"是否正在被攻击"。
- 审批策略取自会话记录，可能不是当前正在运行的会话（报告里会标注多会话是否一致）。
- 通用 harness 的解析基于正则，可能把注释里的 URL 也算进去（宁多报）。
- 不作证书钉扎校验；任何受信任 CA 签发的证书都会被判为公共 CA。
- 未覆盖：依赖链投毒、服务端行为、会话中途切换端点、是否已发生注入。

## 新增 harness

编辑 `WalletGuard.ps1` 里的 `$Known` 数组，加一项 id / 名称 / 配置目录即可。

## License

MIT