//go:build desktop

// Package desktop hosts the editor in a native window instead of a browser tab.
//
// The window is the system webview (WebKitGTK, WKWebView or WebView2) pointed at
// a private loopback port that only this process knows. The interface, its
// handlers and its tests are therefore exactly the same as in headless mode:
// what changes is that the operator gets an application window, and nobody is
// handed a URL to open in a browser.
package desktop

import (
	"context"
	"fmt"
	"os"
	"runtime"

	webview "github.com/webview/webview_go"

	"ssha/internal/ui"
)

// Available reports whether this binary was built with a desktop shell. A build
// without the `desktop` tag is still the full CLI, MCP server and headless
// editor: the GUI is the only thing missing.
const Available = true

// Run opens the window and blocks until it is closed.
func Run(ctx context.Context, srv *ui.Server, version string) error {
	// Creating a GTK window with no display aborts the process, so check first
	// and say something useful instead.
	if runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return fmt.Errorf("没有图形环境（DISPLAY 与 WAYLAND_DISPLAY 都是空的）\n" +
			"  · 在服务器上用：ssha ui --headless\n" +
			"  · 或者从本机通过 SSH 打开窗口：ssh -X")
	}

	url, err := srv.ServeLoopback(ctx)
	if err != nil {
		return fmt.Errorf("无法启动本地服务：%w", err)
	}

	setWindowIcon()

	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("ssha " + version)
	w.SetSize(1200, 800, webview.HintNone)
	w.SetSize(940, 560, webview.HintMin)
	w.Navigate(url)
	w.Run()
	return nil
}
