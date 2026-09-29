# 部署说明

ssha 是单个静态二进制，部署就是「放一个文件 + 装一个 systemd unit」。
这里给两种方式，**先说结论**：

| | 用户服务（`--user`） | 系统服务（`--system`，推荐） |
|---|---|---|
| 需要 root | 不需要 | 需要 |
| 二进制 | `~/.local/bin/ssha` | `/usr/local/bin/ssha` |
| 配置 | `~/.config/ssha/config.yaml` | `/etc/ssha/config.yaml` |
| 凭证可读性 | 你自己（agent 同账号就能读） | **只有 `ssha` 用户和 root** |
| 适合 | 单机自用、试水 | 让 agent 连生产机 |

差别只在**凭证隔离**：用户服务下，agent 进程（和你同账号）在文件系统上就能读到
`~/.config/ssha/` 和 `~/.ssh/`；系统服务下它读不到。想按 §「为什么值得用系统服务」那条做，
就用系统服务。

---

## 一、最快路径

```bash
git clone https://github.com/RogueCultivators/ssha-broker && cd ssha-broker
./packaging/install.sh --user        # 或者： sudo ./packaging/install.sh --system
```

脚本会：构建（带 `git describe` 版本号）→ 装二进制 → 准备配置（**已存在就不覆盖**）→
装并启动 unit → 启用 linger（用户服务）/ 创建 `ssha` 用户（系统服务）→ 打印带 token 的地址。

跑完之后：

```
== open the editor ==
   http://127.0.0.1:8770/?token=REPLACE-WITH-YOUR-TOKEN
```

**把这条 URL 收藏起来**：token 存在 `~/.local/state/ssha/ui.token`（或
`/var/lib/ssha/ui.token`）里，重启不变，所以收藏夹一直有效。

其他可选项：

```bash
./packaging/install.sh --user --port 8900          # 换 UI 端口
sudo ./packaging/install.sh --system --with-mcp    # 同时装 agent 用的 MCP HTTP 服务
sudo ./packaging/install.sh --system --user-name ssha-ops
```

脚本是幂等的：再跑一次只升级二进制和 unit，不动你的配置和审计日志。

---

## 二、手工安装（不想跑脚本）

### 1. 构建并放好二进制

```bash
make build                                     # 产出 ./ssha
install -Dm755 ssha ~/.local/bin/ssha          # 用户服务
sudo install -Dm755 ssha /usr/local/bin/ssha   # 系统服务
ssha version
```

`make install PREFIX=/usr/local`（需权限）也可以，等价于上面第二条。
版本号来自 `git describe`，没有 tag 时是 commit 短哈希。

### 2. 准备配置

```bash
# 用户服务
install -d -m 700 ~/.config/ssha ~/.local/state/ssha
ssha init --out ~/.config/ssha/config.yaml

# 系统服务
sudo install -d -m 700 -o ssha -g ssha /etc/ssha /var/lib/ssha
sudo -u ssha ssha init --out /etc/ssha/config.yaml
```

配置文件里**没有明文密码**（只有 `password_file` / `password_env` 这类来源），但仍然建议 0600：

```bash
chmod 600 ~/.config/ssha/config.yaml
```

密码文件同样：

```bash
install -m 600 /dev/null ~/.config/ssha/prod.pass
read -rs -p 'password: ' P && printf '%s\n' "$P" > ~/.config/ssha/prod.pass
```

### 3. 装 unit

```bash
# 用户服务
install -Dm644 packaging/systemd/ssha-ui.user.service ~/.config/systemd/user/ssha-ui.service
systemctl --user daemon-reload
systemctl --user enable --now ssha-ui

# 系统服务
sudo install -m 644 packaging/systemd/ssha-ui.service /etc/systemd/system/
sudo install -m 644 packaging/systemd/ssha-mcp.service /etc/systemd/system/   # 可选
sudo systemctl daemon-reload
sudo systemctl enable --now ssha-ui
```

用户服务还要让它在**登出后继续跑**：

```bash
loginctl enable-linger "$USER"          # 一般不需要 sudo；失败就 sudo 一次
loginctl show-user "$USER" -p Linger    # 期望 Linger=yes
```

---

## 三、unit 里几个关键点

```ini
ExecStart=%h/.local/bin/ssha --config %h/.config/ssha/config.yaml ui \
          --addr 127.0.0.1:8770 --token-file %h/.local/state/ssha/ui.token
```

- **`--config` 必须写在子命令前面**：它是全局 flag，`ssha ui --config X` 虽然也认，
  但写成上面这样最不容易踩坑。
- **`--token-file`**：不写的话 token 每次启动都变，书签就白收藏了。文件不存在会自动生成，
  权限 0600。
- **`--addr` 默认就是 `127.0.0.1:8770`**。编辑器**拒绝绑定非回环地址**——它显示真实地址、
  未脱敏输出，等于你的控制台，不能监听公网。要从别的机器访问就端口转发：

  ```bash
  ssh -L 8770:127.0.0.1:8770 you@这台机器
  # 然后本地浏览器打开单位里打印的那条带 token 的地址
  ```

- 硬化的那几个开关（`ProtectSystem`、`NoNewPrivileges`、`PrivateTmp`…）对 ssha 是安全的：
  它只读 `~/.ssh` 和 `/etc/ssha`，只写审计日志和 token 文件。

### agent 用的 MCP 服务

`ssha-mcp.service` 跑的是 `ssha mcp --http 127.0.0.1:8765`，给 Codex / Claude Code / Cursor 用。
它**必须**在配置里配了 `server.tokens` 才能对外，否则只会拒绝绑定非回环地址（这是设计）：

```yaml
server:
  http_addr: 127.0.0.1:8765
  tokens:
    - name: my-agent
      value_env: SSHA_TOKEN_AGENT
      tags: [staging]        # 这个 token 只够得着 staging
```

token 的值从环境变量读，所以给它加一个 drop-in（不要写进 unit 文件，那会进 `systemd show`）：

```bash
sudo systemctl edit ssha-mcp
```

```ini
[Service]
Environment=SSHA_TOKEN_AGENT=改成随机串
# 密码来源同理：
# Environment=SSHA_DB_PASSWORD=...
```

```bash
sudo chmod 600 /etc/systemd/system/ssha-mcp.service.d/override.conf
sudo systemctl restart ssha-mcp
```

客户端只配一个 URL 和头：

```json
{ "mcpServers": { "ssha": {
    "url": "http://127.0.0.1:8765/mcp",
    "headers": { "Authorization": "Bearer <token>" } } } }
```

---

## 四、为什么值得用系统服务

用 `--system` 的收益就一句话：**agent 进程在文件系统上读不到你的凭证**。

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin ssha
sudo install -d -m 700 -o ssha -g ssha /etc/ssha /var/lib/ssha
sudo install -m 600 -o ssha -g ssha ssha.yaml /etc/ssha/config.yaml
# 密码文件同样归 ssha 所有、0600
```

之后 `ssha ui` 和 `ssha mcp` 都以 `ssha` 用户跑：

- 你（`ch`）能打开编辑器——因为编辑器是 `ssha` 用户跑的进程，只是**通过 HTTP** 把结果给你；
- 而 agent（和 `ch` 同账号）读不到 `/etc/ssha/config.yaml`、`/var/lib/ssha/ui.token`、
  也读不到 `ssha` 用户的 `~/.ssh`；
- 编辑器里那个 `--reveal`（显示真实地址、不脱敏）也就在你手里，agent 那条路径上
  `ssha mcp` 是强制忽略它的。

这是把手写配置的「约定」变成「权限」的唯一办法。`packaging/install.sh --system` 就是把这套做完。

验证一下隔离真的成立：

```bash
sudo -u ssha ssha --config /etc/ssha/config.yaml hosts test web-1   # 应该成功
cat /etc/ssha/config.yaml                                           # 应该 permission denied
```

---

## 五、日常操作

```bash
# 用户服务
systemctl --user status ssha-ui        # 看状态
systemctl --user restart ssha-ui       # 改完配置重启（其实不必须：编辑自己会重载）
journalctl --user -u ssha-ui -f        # 看日志
journalctl --user -u ssha-ui -n 20 | grep token=   # 找回带 token 的 URL
systemctl --user disable --now ssha-ui # 停掉并取消自启

# 系统服务：把 --user 去掉、前面加 sudo
sudo systemctl status ssha-ui
sudo journalctl -u ssha-ui -n 20 | grep token=
```

打开编辑器的两种方式：

```bash
echo "http://127.0.0.1:8770/?token=$(cat ~/.local/state/ssha/ui.token)"   # 用户服务
sudo cat /var/lib/ssha/ui.token | xargs -I{} echo "http://127.0.0.1:8770/?token={}"
```

或者从 journal 里捞（每次启动都会打一遍；`ExecStart` 里没有 URL，别去那里找）：

```bash
journalctl --user -u ssha-ui -n 50 --no-pager | grep -o 'http://127.0.0.1:[0-9]*/?token=[a-f0-9]*' | tail -1
```

---

## 六、升级

```bash
git pull
./packaging/install.sh --user          # 或 sudo ./packaging/install.sh --system
```

二进制和 unit 会更新，配置不动。编辑器的 token 文件保留，所以书签继续有效。
升级前想稳一点，先看一眼审计链：

```bash
ssha audit verify
```

回滚就是把二进制换回旧版本再 `restart`；配置的每次编辑都会留 `config.yaml.bak`。

---

## 七、排障

| 现象 | 原因 / 处理 |
|---|---|
| 页面打开是「needs the token from the command line」 | 你打开了裸地址。用 `?token=` 那条 URL，或从 `--token-file` 里读 |
| `cannot listen on 127.0.0.1:8770: address already in use` | 端口被占。`ss -ltnp \| grep 8770`，或换 `--port` |
| `status` 里 `Active: activating (auto-restart)` | 看 `journalctl -u ssha-ui -n 50`，通常是 `--config` 指向的文件不存在或校验失败 |
| 改完 unit 不生效 | 忘了 `systemctl --user daemon-reload`（系统服务是 `sudo systemctl daemon-reload`） |
| 登出后服务没了 | `loginctl enable-linger $USER` 没开 |
| 浏览器里列表空、右上角报错 | 那是 401：URL 里的 token 过期（比如上一次跑的），用当前 token 重新打开 |
| `hosts test` 报 `unknown host key` | 该主机没钉主机密钥，且不在 `host_key.known_hosts` 里。用界面里的扫描按钮，或 `ssha host-key <addr> --write` |
| agent 报 `no password source configured` | 密码来源没配。MCP 不会交互式提问，必须给 `password_file` / `password_env` |

---

## 八、卸载

```bash
# 用户服务
systemctl --user disable --now ssha-ui
rm -f ~/.config/systemd/user/ssha-ui.service ~/.local/bin/ssha
rm -rf ~/.config/ssha ~/.local/state/ssha      # 配置 + token + 审计（注意备份）
systemctl --user daemon-reload

# 系统服务
sudo systemctl disable --now ssha-ui ssha-mcp
sudo rm -f /etc/systemd/system/ssha-ui.service /etc/systemd/system/ssha-mcp.service /usr/local/bin/ssha
sudo rm -rf /etc/ssha /var/lib/ssha            # 先备份审计日志
sudo userdel ssha
sudo systemctl daemon-reload
```

审计日志（`audit.jsonl`）是唯一不可再生的东西，卸载前先拷走：
`~/.local/share/ssha/` 或配置里 `audit.path` 指的位置。
