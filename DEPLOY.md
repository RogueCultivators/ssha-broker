# 部署说明

ssha 有一个桌面应用（配置编辑器）和一个命令行 / MCP 服务端。两者是同一个二进制，
桌面界面在 `desktop` 构建标签后面，所以**纯 Go 构建照旧能在任何地方编译**，只是没有窗口。

| 你想要 | 怎么装 |
|---|---|
| 在自己电脑上编辑配置 | `.deb` / AppImage / `.exe` / macOS `.zip`，或者 `./packaging/install.sh --user` |
| 让 agent 通过 MCP 连生产机 | `sudo ./packaging/install.sh --system --with-mcp` |
| 纯命令行 / 无显示器 | `go build ./cmd/ssha`，用 `ssha run` / `ssha mcp` |

---

## 一、安装桌面应用

### 用打包好的（推荐）

从 [Releases](https://github.com/RogueCultivators/ssha-broker/releases) 下载：

- **Debian / Ubuntu**：`sudo apt install ./ssha_<版本>_amd64.deb` —— 装完应用菜单里就有 ssha
- **任意 Linux**：`chmod +x ssha-<版本>-x86_64.AppImage && ./ssha-<版本>-x86_64.AppImage`
- **Windows**：解压 zip 得到 `ssha.exe`，双击。**只有一个文件**，不用带任何 DLL
- **macOS**：解压 zip 得到 `ssha.app`，拖进「应用程序」

> AppImage 和 deb **不带浏览器引擎**——窗口用的是系统自带的 WebKitGTK。
> 现在的桌面发行版都有；deb 已经把依赖写进 `Depends`，AppImage 需要你自己确认装了
> `libwebkit2gtk-4.1`（或 4.0）和 `libgtk-3`。
> Windows 侧需要 WebView2 运行时，Windows 10/11 自带；ssha 会自己去找到它，
> 所以发行包里没有 `WebView2Loader.dll` 这个文件。
>
> 一个已知的取舍：`ssha.exe` 是**控制台子系统**的，双击会同时开一个黑窗口。
> 这样 `ssha run` / `ssha mcp` 在终端里才有输出——它首先是个命令行工具。
> 如果你更想要纯粹的双击体验，说一声，改成窗口子系统是几分钟的事。

### 用脚本从源码装

```bash
git clone https://github.com/RogueCultivators/ssha-broker && cd ssha-broker
./packaging/install.sh --user        # 不需要 root
```

它会：编译桌面版（缺 GTK/WebKit 开发包时退回纯命令行并提示）→ 装二进制到
`~/.local/bin/ssha` → 装图标到 `~/.local/share/icons/hicolor/*/apps/` → 装启动器到
`~/.local/share/applications/ssha.desktop` → 刷新桌面缓存。

然后从**应用菜单**打开 ssha，或者命令行 `ssha ui`。没有后台服务，没有端口，没有浏览器。

系统级（所有用户都能从菜单打开）：`sudo ./packaging/install.sh --system`。

### 从源码手动构建

```bash
# 只看命令行
go build -o ssha ./cmd/ssha

# 带桌面窗口（需要 GTK3 + WebKitGTK 开发包）
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev     # Debian/Ubuntu
./scripts/build-desktop.sh ssha                          # 会自动处理 4.0/4.1 的差异
```

Ubuntu 24.04 起只剩 `webkit2gtk-4.1`，而 Go 绑定写死了 `webkit2gtk-4.0`。
`scripts/build-desktop.sh` 会临时生成一个别名 `.pc` 文件来弥合——底层的 C++ 库运行时
本来就同时加载 4.1 和 4.0，所以这不是打补丁，也不需要 vendor 任何东西。

打包：

```bash
make desktop          # dist 之外的 ./ssha，带窗口
make package-deb      # 需要 nfpm
make package-appimage # 需要 appimagetool
make package-macos    # 只在 macOS 上有意义
```

---

## 二、配置放哪

| | 路径 |
|---|---|
| 配置 | `~/.config/ssha/config.yaml`（系统级装在 `/etc/ssha/config.yaml`） |
| 密码 | 配置旁边的 `secrets/<主机名>.password`，0600 |
| 审计日志 | `~/.local/share/ssha/audit.jsonl`（或配置里 `audit.path`） |

第一次打开时如果没有配置，ssha 会从模板生成一份。密码直接在界面里输，
它会写成 0600 的文件，配置里只留一行 `password_file` 指过去。

配置文件里**没有明文密码**，但主机清单和策略都在里面，建议保持 0600。

---

## 三、让 agent 用起来

两条路，可以只用一条，也可以都用。

### 1. Skill（用命令行工具的 agent：pi、Claude Code 之类）

在桌面应用的「**接入 agent**」面板里，点一下「安装」——它会写到你选的位置：

| 位置 | 谁读它 |
|---|---|
| `~/.agents/skills` | pi 和 Claude Code 都认（通用位置） |
| `~/.pi/agent/skills` | pi 自己的位置 |
| `~/.claude/skills` | Claude Code 自己的位置 |

等价命令：`ssha skill install`。面板里还能「复制 SKILL.md」，给没有 ssha 的机器用。

### 2. MCP（Codex、Claude Code、Cursor 等）

**stdio，最省事**——把这段放进对应客户端的配置：

```json
{ "mcpServers": { "ssha": { "command": "/home/你/.local/bin/ssha", "args": ["mcp"] } } }
```

Codex 是 `~/.codex/config.toml`：

```toml
[mcp_servers.ssha]
command = "/home/你/.local/bin/ssha"
args = ["mcp"]
```

路径用**绝对路径**：从桌面会话启动的客户端，PATH 未必和你 shell 里一样。
桌面应用的「接入 agent」面板会直接生成好这段，带复制按钮。

**HTTP，给别的机器上的 agent**：

```bash
sudo ./packaging/install.sh --system --with-mcp
```

这会在 `/etc/ssha/config.yaml` 上跑一个 `ssha-mcp.service`，用专用 `ssha` 用户，监听
`127.0.0.1:8765`。要对外必须配 token：

```yaml
server:
  http_addr: 127.0.0.1:8765
  tokens:
    - name: my-agent
      value_env: SSHA_TOKEN_AGENT
      tags: [staging]        # 这个 token 只够得着 staging
```

token 的值从环境变量读，用 drop-in 给（别写进 unit 文件，那会进 `systemctl show`）：

```bash
sudo systemctl edit ssha-mcp
```

```ini
[Service]
Environment=SSHA_TOKEN_AGENT=改成随机串
Environment=SSHA_DB_PASSWORD=...
```

```bash
sudo chmod 600 /etc/systemd/system/ssha-mcp.service.d/override.conf
sudo systemctl restart ssha-mcp
```

### 为什么 MCP 服务要用专用用户

这是唯一能让「agent 读不到凭证」变成权限而不是约定的办法：`ssha-mcp` 以 `ssha` 用户跑，
配置在 `/etc/ssha`（0600，属主 ssha），而 agent 进程和你在同一个账号下，**在文件系统上读不到**。

```bash
sudo -u ssha ssha --config /etc/ssha/config.yaml hosts test web-1   # 成功
cat /etc/ssha/config.yaml                                           # permission denied
```

注意：桌面应用是以**你自己**的身份跑的（它要编辑你的 `~/.config/ssha/`），
所以它能看到全部凭证——它本来就是你运维用的控制台。要让 agent 也读不到，
agent 走 MCP 服务那条路。

---

## 四、无显示器的机器

桌面窗口需要图形环境。在服务器上、CI 里、或者你只想通过 SSH 转发用浏览器时：

```bash
ssha ui --headless                          # 起一个本地服务并打印带 token 的地址
ssha ui --headless --addr 127.0.0.1:8770
```

想要它常驻：

```bash
./packaging/install.sh --user --headless-service          # 用户级
sudo ./packaging/install.sh --system --headless-service   # 系统级
```

从别的机器访问（它是故意只监听回环的）：

```bash
ssh -L 8770:127.0.0.1:8770 you@那台机器
# 然后本地浏览器打开 journalctl 里打印的那条带 token 的地址
journalctl --user -u ssha-ui -n 20 --no-pager | grep -o 'http://127.0.0.1:[0-9]*/?token=[a-f0-9]*' | tail -1
```

---

## 五、日常操作

```bash
# 桌面应用
ssha ui                      # 打开窗口（应用菜单里也是这个）
ssha ui --headless           # 不开窗口，改成服务

# 命令行
ssha hosts list && ssha hosts test web-1
ssha hosts find payment      # 按备注找机器
ssha audit verify            # 校验审计哈希链
ssha version

# 后台服务（只有用 --headless-service / --with-mcp 装过才有）
systemctl --user status ssha-ui        # 或 sudo systemctl status ssha-mcp
journalctl --user -u ssha-ui -f
```

## 六、升级

- 装了包：`sudo apt install ./ssha_<新版本>_amd64.deb`
- 脚本装的：`git pull && ./packaging/install.sh --user`
- 升级前想稳一点：`ssha audit verify`

配置、密钥和审计日志都不会被动。桌面应用的配置每次编辑都会留 `config.yaml.bak`。

## 七、排障

| 现象 | 处理 |
|---|---|
| `ssha ui` 说「没有图形环境」 | 用 `ssha ui --headless`，或从本机 `ssh -X` |
| `ssha ui` 说「这个二进制没有编译桌面界面」 | 你装的是纯 Go 版本。用打包版，或 `./scripts/build-desktop.sh`；现在要也行：`--headless` |
| 窗口打开是空白 | Linux 上大概率缺 `libwebkit2gtk`：`sudo apt install libwebkit2gtk-4.1-0` |
| Windows 双击没反应 | 缺 WebView2 运行时（Windows 10/11 自带，精简版系统可能被删） |
| 应用菜单里没图标 | `gtk-update-icon-cache -f -t ~/.local/share/icons/hicolor`，或者重新登录 |
| 页面显示「这个界面需要命令行里那个 token」 | 你打开的是裸地址。用打印出来的带 `?token=` 的那条，或从 `--token-file` 里读 |
| `cannot listen on ... address already in use` | 端口被占（老的 headless 服务？）。`ss -ltnp \| grep 8770` |
| agent 报 `no password source configured` | 该主机没配密码。在桌面应用里选「密码」直接输入，或填 `password_file` / `password_env` |
| `hosts test` 报 `unknown host key` | 没钉主机密钥。界面里点「扫描主机密钥」，或 `ssha host-key <addr> --write` |
| 找不到 skill | 确认装到了 agent 会扫的目录（通常是 `~/.agents/skills`），然后重启 agent |

## 八、卸载

```bash
# 用户级
rm -f ~/.local/bin/ssha ~/.local/share/applications/ssha.desktop
rm -rf ~/.local/share/icons/hicolor/*/apps/ssha.png
rm -rf ~/.config/ssha ~/.local/share/ssha      # 配置 + 密码 + 审计，先备份！
gtk-update-icon-cache -f -t ~/.local/share/icons/hicolor

# 系统级
sudo systemctl disable --now ssha-mcp ssha-ui
sudo rm -f /usr/local/bin/ssha /usr/share/applications/ssha.desktop
sudo rm -rf /usr/share/ssha /etc/ssha /var/lib/ssha
sudo userdel ssha
```

审计日志（`audit.jsonl`）是唯一不可再生的东西，卸载前先拷走。
