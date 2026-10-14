ssha for Windows
================

这是 ssha 的 Windows 版：一个 SSH 中转/代理，把主机清单、凭证和策略放在本机，
agent（Claude Code、Cursor、pi 等）只发受控的请求，看不到密码和私钥。
同一个 exe 也是命令行工具和 MCP 服务端。


压缩包里有什么
--------------

  ssha.exe             命令行版。CLI 和 MCP 服务端，在终端里用。
  ssha-ui.exe          窗口版。双击只开配置窗口，不带黑框控制台。
  install.ps1          安装脚本：装到用户目录、加 PATH、建快捷方式、设置自启动。
  uninstall.ps1        卸载脚本。
  README-Windows.txt   本文件。


快速开始
--------

1) 解压到一个文件夹。

2) 打开 PowerShell（不用管理员），cd 到解压出来的文件夹，然后：

     powershell -ExecutionPolicy Bypass -File .\install.ps1

   如果提示脚本被系统阻止（从网上下的 zip 会带“阻止”标记），先跑一次：

     Unblock-File .\install.ps1, .\uninstall.ps1

   脚本会：把两个 exe 装到 %LOCALAPPDATA%\Programs\ssha，加进用户 PATH，
   在开始菜单和桌面建 "ssha" 快捷方式，生成一份起始配置，并默认设置
   “登录时自动打开 ssha 窗口”。

3) 从开始菜单点 "ssha"，在窗口里添加主机，或者直接编辑配置：

     %USERPROFILE%\.config\ssha\config.yaml

   配置里的密码在界面里输入后会加密保存到
   %USERPROFILE%\.config\ssha\secrets\，不以明文落盘。


自启动
------

安装脚本默认让 ssha 窗口在登录时自动打开。用 -Autostart 换：

  -Autostart ui      登录时打开 ssha 窗口（默认）
  -Autostart mcp     登录时在后台跑 MCP 服务（http://127.0.0.1:8765），不开窗口
  -Autostart both    两个都要
  -Autostart none    都不要

自启动就是“启动”文件夹里的快捷方式，想改或想删，直接去：

  %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup


命令行用法
----------

装完之后新开一个终端窗口（PATH 才会生效）：

  ssha hosts list                      列出主机和策略
  ssha run web-1 -- systemctl status nginx
  ssha download web-1 /etc/hosts -
  ssha host-key web-1 --write          扫描并钉住主机密钥
  ssha mcp                             给 agent 用的 MCP（stdio）
  ssha-ui ui                           开配置窗口（和快捷方式一样）

ssha.exe 是控制台程序：在终端里跑有输出，双击会同时开一个控制台窗口。
想要纯粹的双击体验就用 ssha-ui.exe，或者开始菜单里的快捷方式。


给 agent 接 MCP
---------------

Agent 配置里让 ssha 作为 MCP 服务端。本机 stdio 最简单：

  { "mcpServers": { "ssha": { "command": "ssha", "args": ["mcp"] } } }

要让多个 agent / 远程连接共用，用常驻的 HTTP 模式（自启动 -Autostart mcp 就是它）：

  ssha mcp --http 127.0.0.1:8765

HTTP 模式要先在配置里配 server.tokens，否则只监听本机回环。


依赖
----

窗口用的是系统自带的 WebView2。Windows 10/11 都带；精简系统如果删了，
去微软官网装 “Evergreen WebView2 Runtime”。


卸载
----

  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1

默认保留配置、加密的密码和审计日志（它们是你的数据）。要全删：

  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -Purge


安全边界
--------

凭证留在这台机器上，agent 拿不到。同一个 Windows 用户能读到解封密钥，
所以防的是“密码不以明文躺在磁盘上”和“agent 看不到凭证”，
不是防本机上的同一个用户。
