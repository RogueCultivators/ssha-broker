# ssha — 给 AI agent 用的 SSH 代理网关

`ssha` 是一个 **agent 原生的 SSH broker（代理网关）**：把主机清单、SSH 凭证、
访问策略和审计日志集中到一个本地进程里，再以 **MCP server** 和 **CLI + Skill**
两种形式暴露给 Codex / pi / Claude Code / Cursor 这类编码 agent。

一句话：**agent 拿不到私钥，只能按策略执行命令，每一步都被记录且可校验。**

```
        MCP (stdio / HTTP)          CLI (ssha run ...)        pi skill
codex / pi / claude / cursor ─────┐         │                    │
                                  ▼         ▼                    ▼
                       ┌───────────────────────────────────────────────┐
                       │              ssha broker (Go)                 │
                       │  policy engine   allow / readonly / deny      │
                       │  audit log       JSONL + SHA-256 hash chain   │
                       │  conn pool       x/crypto/ssh + SFTP          │
                       │  credentials     key / ssh-agent / password   │
                       └───────────────────────┬───────────────────────┘
                                               │ SSH
                                               ▼  目标机
```

---

## 1. 为什么需要它

现有三类方案各缺一块：

| 方案 | 代表项目 | 缺什么 |
|---|---|---|
| SSH MCP server | `classfang/ssh-mcp-server`、`tufantunc/ssh-mcp`、`bvisible/mcp-ssh-manager`（37 个工具） | 凭证明文放客户端配置；没有策略层；没有结构化审计；工具太多，模型容易选错 |
| 堡垒机 / 跳板机 | Teleport、JumpServer、next-terminal、`ovh/the-bastion` | 太重（Web + DB + CA）；面向人类运维；没有 agent 原生接口；审计是会话录像而不是可编程的结构化记录 |
| agent 侧集成 | pi 的 `examples/extensions/ssh.ts` | 只能把整个工具集切到远端；没有多主机概念；没有策略和审计 |

**交集是空的**：没有一个「薄、专、可审计」的 agent SSH 网关。所以自己写，而且工作量可控
（核心约 2500 行 Go，单一静态二进制，无 cgo）。

### 与裸 MCP SSH server 的关键差异

| | 裸 ssh-mcp | ssha |
|---|---|---|
| 私钥位置 | agent 所在机器 | 只在 broker，agent 永远拿不到 |
| 权限控制 | 无（等于 shell） | 每主机 `allow` / `readonly` / `deny` + 允许列表 + 危险命令基线拦截 |
| readonly 绕过 | — | 默认拒绝 shell 元字符，`ls; rm -rf /tmp` 无法匹配 `^ls` |
| 审计 | 日志文本 | 每条命令结构化记录 + SHA-256 哈希链，`ssha audit verify` 可检测篡改 |
| 工具数量 | 动辄 30+ | 7 个，面向模型选择准确率设计 |
| 超时/输出上限 | agent 说了算 | 策略设上限，agent 只能收紧不能放宽 |
| 多主机 | 逐个 | `ssh_exec_many` 按 tag 并行下发 |
| 凭证类型 | 通常是 key 文件 | key / ssh-agent / password(env) / 加密 key + passphrase / ProxyJump |

---

## 2. 安装

```bash
git clone <this repo> && cd ssh-agent
go build -o ssha ./cmd/ssha
install -m 0755 ssha ~/.local/bin/ssha      # 或者 go install ./cmd/ssha

ssha version
```

要求 Go 1.25+（依赖 `modelcontextprotocol/go-sdk`）。产物是单个静态二进制，可交叉编译到
Linux/macOS/Windows。

## 3. 快速开始

```bash
ssha init                     # 生成 ssha.yaml 模板
$EDITOR ssha.yaml             # 填 hosts
ssha hosts list               # 确认能读到主机
ssha hosts show prod-web      # 看这一台机器到底允许什么
ssha policy check prod-web -- systemctl restart nginx   # 空跑，不执行不审计
ssha run prod-web -- systemctl status nginx
ssha run prod-web --json -- uname -r
ssha audit ls --decision denied
ssha audit verify             # 校验哈希链
ssha skill install            # 把 skill 装到 ~/.agents/skills/ssha-agent
ssha mcp                      # 以 MCP stdio server 启动
```

配置文件查找顺序：`--config` → `$SSHA_CONFIG` → `./ssha.yaml` → `~/.config/ssha/config.yaml`
→ `/etc/ssha/config.yaml`。

---

## 4. 配置

完整带注释的模板由 `ssha init` 生成，见 [`internal/cli/template.yaml`](internal/cli/template.yaml)。

### 4.1 主机 `hosts[]`

```yaml
hosts:
  - name: prod-web
    description: 公网 Web 前端，agent 只读
    addr: 10.0.0.10
    port: 22
    user: deploy
    tags: [prod, web]
    work_dir: /srv/app            # 默认工作目录
    env: { APP_ENV: prod }        # 默认环境变量
    proxy_jump: bastion           # 通过跳板机（引用另一台 host 的 name）
    auth:
      type: key                   # key | agent | password
      key_path: ~/.ssh/id_ed25519
      # passphrase_env: SSHA_KEY_PASSPHRASE   # 加密私钥的口令来源
      # key_env: SSHA_PRIVATE_KEY             # 直接放 PEM 内容（CI 场景）
    host_key:
      known_hosts: ~/.ssh/known_hosts
      # fingerprints: ["SHA256:..."]  # 或直接钉指纹
      # insecure: false               # 关掉校验，仅测试用
    policy:
      mode: readonly
```

- `type: agent` 走本地 `SSH_AUTH_SOCK`，磁盘上不放私钥。
- `type: password` 从 `password_env` 指向的环境变量读取，配置文件里不留密码。
- 主机密钥默认 **fail-closed**：没有 known_hosts 或指纹就拒绝连接，并给出可执行的报错
  （会把服务器实际提供的指纹和 known_hosts 里的都打印出来）。
- `proxy_jump` 支持一层跳板机，跳板机自身也可以有独立策略（通常设成 `deny`）。

### 4.2 策略 `policy`

三种模式，**deny 永远优先**：

| 模式 | 行为 |
|---|---|
| `allow` | 除 `deny_commands` / 内置基线外的命令都允许 |
| `readonly` | 只允许 `allow_commands` 命中的命令（正则，锚定在开头），并且拒绝写文件 |
| `deny` | 全部拒绝（用于跳板机、敏感机器） |

```yaml
policy:
  mode: allow
  timeout: 60s
  max_output_bytes: 262144
  deny_commands:            # 正则，命令串中出现即拒绝
    - 'rm\s+-rf\s+/'
    - '\bmkfs\b'
    - '\b(shutdown|reboot|poweroff)\b'
  deny_paths:               # SFTP 上传/下载路径黑名单
    - '^/etc/shadow$'
    - '/\.ssh/id_'
  allow_shell_metacharacters: false   # readonly 下是否允许 ; | & < > \` 换行 $(
  disable_baseline: false             # 是否关闭内置危险命令基线
```

内置基线（始终生效，除非 `disable_baseline`）：fork bomb、`mkfs`、`dd of=/dev/sd*`、
`rm -rf /`、`shutdown/reboot/halt/poweroff`、`> /etc/passwd`、`wipefs`、
`chmod -R 777 /`、`userdel/groupdel` 等。

**关于 readonly 的安全边界**（重要）：
用正则白名单匹配整条 shell 字符串本质上是可绕过的，`^ls` 挡不住 `ls; rm -rf /tmp`。
所以 readonly 模式默认 **拒绝 shell 元字符**（`;` `|` `&` `<` `>` 反引号 换行 `$(`），
一条命令只能是一个简单命令。需要管道时显式打开 `allow_shell_metacharacters: true`，
并理解你放弃了这层保护。

`timeout` / `max_output_bytes` 是**上限**：agent 请求里只能写更小的值，broker 会 clamp。

### 4.3 审计 `audit`

```yaml
audit:
  path: ~/.local/share/ssha/audit.jsonl
  store_output: true        # 是否把 stdout/stderr 写进审计
  max_field_bytes: 65536    # 每条流的截断长度
```

每条命令一行 JSON，字段包括：`id / time / session_id / seq / actor / machine /
agent{tool,model,session_id} / type / host / command / path / cwd / decision / reason /
exit_code / duration_ms / bytes / truncated / stdout / stderr / prev_hash / hash`。

`hash = sha256(prev_hash + "\n" + 规范化JSON)`，形成哈希链。任何改写、删行、换序都会
被 `ssha audit verify` 发现：

```
$ ssha audit verify
ok: 20 record(s) verified, chain intact (/home/ch/.local/share/ssha/audit.jsonl)
$ ssha audit verify          # 手工改了一条 command 之后
ssha: audit verification FAILED after 1 record(s): record #2 (...): hash mismatch, record was modified
```

写入用 `flock` + `O_APPEND`，多进程并发追加也不会破坏链。

### 4.4 HTTP MCP 与 token 作用域

```yaml
server:
  http_addr: 127.0.0.1:8765
  tokens:
    - name: ci
      value_env: SSHA_TOKEN_CI          # 值只从环境变量读
      tags: [staging]                   # 这个 token 只能碰 staging 标签的机器
    - name: oncall
      value_env: SSHA_TOKEN_ONCALL
      hosts: ["web-*", "db-*"]          # 按主机名 glob 限定
```

- `ssha mcp` 默认 stdio，给本机的 agent 用。
- `ssha mcp --http ADDR` 走 streamable HTTP + Bearer token；**没有配 token 时绑定
  非 loopback 地址会直接拒绝启动**（防止裸奔）。
- 每个 token 有独立的 broker 视图：`ssh_list_hosts` 看不到无权主机，`ssh_exec` 会被
  拒绝，`ssh_audit` 也只会返回它有权主机的记录。

---

## 5. 接入各种 agent

### 5.1 MCP（Codex / Claude Code / Cursor）

stdio 模式是通用做法。

**Codex** `~/.codex/config.toml`：

```toml
[mcp_servers.ssha]
command = "ssha"
args = ["mcp"]
```

**Claude Code**：

```bash
claude mcp add ssha -- ssha mcp
```

**Cursor** `~/.cursor/mcp.json`：

```json
{ "mcpServers": { "ssha": { "command": "ssha", "args": ["mcp"] } } }
```

**团队共享 / 远程**：`ssha mcp --http 0.0.0.0:8765`，客户端带
`Authorization: Bearer $SSHA_TOKEN_CI`，token 到 `server.tokens` 里配。

暴露的 7 个工具：

| 工具 | 用途 |
|---|---|
| `ssh_list_hosts` | 列出可达主机、tag、策略模式、上限 |
| `ssh_exec` | 单机执行命令，返回 stdout/stderr/exit_code/audit_id |
| `ssh_exec_many` | 按 name 或 tag 并行下发到一批机器 |
| `ssh_upload` | SFTP 写文件（父目录自动创建） |
| `ssh_download` | SFTP 读文件（UTF-8 直出，二进制转 base64） |
| `ssh_policy_check` | 空跑策略，不执行不审计 |
| `ssh_audit` | 查询审计日志 |

> 工具描述里写死了行为约定：denied 不要重试、非零 exit_code 是正常结果、
> timeout/输出上限只能收紧。这些是给模型看的「接口契约」。

### 5.2 pi — 方式 A：Skill（推荐）

```bash
ssha skill install              # 装到 ~/.agents/skills/ssha-agent/SKILL.md
```

skill 教模型用 `ssha hosts list` / `policy check` / `run --json` / `audit` 这套 CLI 工作流，
并在描述里声明「用户要求操作远端主机时」触发。pi 会扫描 `~/.agents/skills/`，
Claude Code 也认这个路径。

### 5.3 pi — 方式 B：原生 Extension

```bash
cp extensions/pi/ssha-agent.ts ~/.pi/agent/extensions/
# 或临时加载： pi --extension ./extensions/pi/ssha-agent.ts
```

注册 `ssh_exec` / `ssh_list_hosts` / `ssh_policy_check` / `ssh_audit` 四个原生工具，
底层还是调 `ssha --json`，但结果是结构化的，还能做截断和自定义渲染。

两种方式可以共存：MCP/Extension 提供结构化工具，Skill 提供「什么时候用、怎么用」的知识。

### 5.4 任意有 bash 的 agent

只要能执行命令，就能用 `ssha run --json ...`，退出码语义明确：

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 本地失败 / 命令根本没跑起来 |
| 2 | CLI 用法错误 |
| 7 | 远端命令自身的退出码（原样透传，>125 归一到 1） |
| 77 | 被策略拒绝（`EX_NOPERM`） |

---

## 6. 安全模型

**保护的是什么**

1. **凭证不出 broker**：agent 只传主机名，私钥/密码/口令都留在 broker 进程可达的地方。
2. **策略前置**：`ssh_exec`/`upload`/`download` 都在建立连接*之前*做策略判定，拒绝的
   请求不会触达目标机，但依然写审计（`decision: denied` + 原因）。
3. **审计不可静默篡改**：哈希链 + `audit verify`。sha256 链只保证「可检测」，不保证
   「不可删除」——要防删除请把 `audit.jsonl` 同步到外部（rsync/WORM 存储）。
4. **最小工具面**：没有 `ssh_shell` 交互式会话，没有端口转发（见 Roadmap），减少了
   被诱导做坏事的表面积。
5. **上限不可突破**：超时和输出上限由策略设定，agent 只能更严格。

**已知限制（诚实说明）**

- 策略是**字符串层面**的，不是 shell 语义层面的。`readonly` + 关闭元字符能挡住绝大多数
  绕过，但 `sudo` 的配置、目标机上的 wrapper 脚本、`find -exec` 这类不在白名单里的东西
  仍然是攻击面。真正的隔离要靠目标机自身的权限（专用低权账号、sudoers 白名单）。
- `env` 由 agent 可控（`-e KEY=VAL`），目标机上若有依赖环境变量的 setuid/脚本可能有风险。
- broker 以当前 OS 用户的权限运行，配置文件对它可读即可读到凭证来源路径。
- HTTP 模式目前是共享 Bearer token，没有 per-user 身份、限流和 mTLS。

**建议的部署姿势**：每台 agent 一个低权专用账号（不是 root），`readonly` 为默认，
只有确实需要的机器开 `allow`，把审计目录同步出去。

---

## 7. CLI 参考

```
ssha init [--out ssha.yaml] [--force]
ssha hosts [list] [--tag T] [--name GLOB] [--all]
ssha hosts show <name>
ssha run <host> [--cwd DIR] [-e K=V] [--timeout 30s] [--max-output N] [--dry-run] [--json] [--] <cmd>
ssha multi [--host H]... [--tag T]... [--concurrency N] [--] <cmd>
ssha upload <host> <local|-> <remote> [--mode 0644]
ssha download <host> <remote> <local|-> [--max-bytes N]
ssha policy check <host> [--] <cmd>
ssha audit ls [--host H] [--type exec|upload|download] [--decision allowed|denied] [--limit N] [--since 1h]
ssha audit show <id>
ssha audit verify
ssha mcp [--http ADDR] [--verbose]
ssha skill install [--dir DIR] [--force] | ssha skill print
ssha version
```

所有命令都支持 `--json`；flag 可以放在主机名前面或后面（`ssha run web-1 --cwd /etc -- ls`
和 `ssha run --cwd /etc web-1 -- ls` 等价），`--` 之后一律原样作为远端命令。

---

## 8. 开发与测试

```bash
go build ./...            # 构建
go vet ./...              # 静态检查
go test ./...             # 单元测试（config / policy / audit，无需网络）
./scripts/e2e.sh          # 端到端：起一个 sshd 容器，跑完 CLI + MCP + 篡改检测
```

`scripts/e2e.sh` 会：构建二进制 → 生成临时密钥 → `docker build` 一个 alpine sshd →
`ssh-keyscan` 钉住主机密钥 → 写配置 → 逐项断言 CLI 与 MCP 的行为（策略模式、退出码透传、
主机密钥校验、输出截断、上传下载、只读写保护、审计篡改检测、skill 安装、MCP stdio 的
initialize/tools/list/tools/call、HTTP healthz 与「无 token 拒绝非 loopback」）。
失败即非 0 退出，可以直接用在 CI 里。

`scripts/mcp_smoke.py` 用原始 JSON-RPC 走一遍 MCP 的 initialize / tools/list / tools/call。

代码结构：

```
cmd/ssha/                 入口
internal/config/          配置加载、校验、策略合并
internal/policy/          策略编译与判定（含基线拦截、元字符规则）
internal/audit/           JSONL + 哈希链审计，flock 并发安全
internal/sshx/            x/crypto/ssh 封装：连接池、执行、SFTP、ProxyJump、主机密钥校验
internal/broker/          核心：串起 config + policy + audit + sshx（CLI 和 MCP 共用）
internal/mcpsrv/          MCP server（7 个工具）+ HTTP token 作用域
internal/cli/             命令行
skills/ssha-agent/        agent skill（go:embed 进二进制）
extensions/pi/            pi 扩展（可选的原生工具）
scripts/                  e2e 与 MCP 冒烟脚本
```

设计上的一条硬规则：**CLI 和 MCP 都只是 broker 的薄适配层**，不允许各自实现一份策略
或审计逻辑，否则两边一定会分叉。

---

## 9. Roadmap

- [ ] 交互式会话与端口转发（`ssh_shell` / `ssh_tunnel`），带会话录像（asciinema cast）
- [ ] 会话级别审批：`require_approval_commands` + 一次性 token
- [ ] 审计导出到 syslog / OTLP，支持外部 WORM 存储
- [ ] `ssha serve` 常驻模式：Windows 命名管道 / Unix socket，agent 走本地 RPC
- [ ] 凭证加密仓（age/sops）与 OS keyring
- [ ] 每命令资源配额（CPU/内存 cgroup）、命令去重与限流
- [ ] Web UI：主机清单 + 审计检索（只读）

## 10. License

MIT
