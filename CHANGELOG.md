# 更新日志

## 0.2.0 — 2026-10-20

### 新功能

- **Git 中转（`ssha git`）**：按主机名和路径前缀匹配账号，支持 SSH 私钥和 HTTPS 用户名 + token。
  Agent 只能请求 `fetch` / `pull` / `push` / `clone` / `ls-remote`，看不到密码、token 或私钥。
  凭证留在本机，不进 URL、参数、审计日志或 MCP 输出。force push 默认拒绝，除非账号显式允许。
  MCP 新增 `git_accounts` 和 `git` 两个工具，界面新增 Git 页（Ctrl+4）。
- **界面管理密码**：第一次打开 `ssha ui` 要求设置管理密码，之后每次启动需要解锁。
  它只锁配置界面；CLI 和 MCP 不需要解锁，行为不变。会话 30 分钟空闲失效，改密码会踢掉旧会话。
- **保存的密码加密落盘**：界面里输入的 SSH 密码、私钥口令、Git 密码/口令用 AES-256-GCM
  加密后写到 `secrets/`（`SSHA1:` 前缀），密钥是自动生成的 `secrets/.seal-key`。
  已有的明文 `secrets/*.password` / `*.passphrase` 会在下次启动时自动迁移。
- **审计日志独立页面**：从主机编辑器里的小表格改成整页工作区：左边按结果/类型/主机/时间分类，
  中间按天列出记录，右边看一条记录的命令、原因和完整输出。Ctrl+2 仍可打开。
- **Windows 安装包**：zip 里带 `install.ps1` / `uninstall.ps1` 和两个 exe。
  安装脚本装到用户目录、加 PATH、建开始菜单和桌面快捷方式、生成起始配置，
  并可设置登录自启动（窗口 / MCP / 两者 / 关闭）。`ssha-ui.exe` 是窗口子系统，
  双击直接打开配置窗口，不附带控制台。

### 修复

- **主机密钥扫描不再用虚构用户**：以前用 `ssha-host-key-scan` 探测，sshd 记 `Invalid user`，
  fail2ban 几次就会封掉出口 IP。现在用配置里的用户和公钥扫描；没有对应用户时直接匿名读取密钥，
  连用户名都不发。
- **Git 账号支持 `host:port`**：自建 Git 可以写 `hosts: [git.example.com:14444]`。
  不带端口匹配所有端口，带端口只匹配该端口。
- **带端口的 HTTPS 凭据不再被自己拒绝**：git 在非默认端口时把端口拼进凭据请求的 host，
  ssha 以前只存主机名，导致 `credential request does not match the granted host`。
  现在 grant 记录实际端口并一起比对。
- **`ssha git --remote` 真正传给 git**：以前只用来选账号，实际命令仍走 `origin`，
  可能 push 到错误的仓库。现在会执行 `git push enterprise main` 这种形式。
- **Windows 双击 exe 直接开窗**：窗口版无参数时默认打开编辑器；启动失败会弹错误框，
  不再静默退出。
- **同一把主机密钥在 22 端口已验证时，其他端口也接受**，不必为换端口重新钉一次。
- `ssha --help` / `ssha <cmd> --help` 正常返回，不再当成用法错误。
- 界面改全局策略时不再清掉手写的 allow / deny 列表。

### 变更与升级注意

- Git 账号的 `hosts` 现在可以带端口；已有配置不需要改。
- `ssha git <op>` 里 `--remote` 之后的参数按 refspec 处理；远端用 `--remote` 指定，默认 `origin`。
- 管理密码只锁界面。忘了密码：删除 `secrets/ui-auth.json` 即可重新设置，已保存的 SSH 密码不受影响。
- 丢了 `secrets/.seal-key` 就解不开已保存的密码，只能重新输入；它不会出现在任何命令或输出里。
- Windows 包不再只有一个 exe：`ssha.exe`（命令行 + MCP）和 `ssha-ui.exe`（窗口）。

### 安装包

- Linux：`.deb`（Debian/Ubuntu）或 `AppImage`（任意发行版，需要系统带 WebKitGTK 和 GTK3）。
- Windows：`ssha-<版本>-windows-x64.zip`，解压后运行 `install.ps1`。
- macOS：`ssha.app` 的 zip（或 dmg）。
