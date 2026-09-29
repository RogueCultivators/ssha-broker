//go:build !desktop

package desktop

import (
	"context"
	"fmt"

	"ssha/internal/ui"
)

// Available reports whether this binary was built with a desktop shell.
const Available = false

// Run explains how to get a window instead of failing obscurely. The plain build
// stays pure Go: it is the CLI, the MCP server and the headless editor, and it
// compiles anywhere without a C toolchain or GTK headers.
func Run(context.Context, *ui.Server, string) error {
	return fmt.Errorf("这个二进制没有编译桌面界面（纯 Go 构建）\n" +
		"  · 要窗口：装 webkit2gtk-4.1 和 gtk+-3.0 的开发包，然后\n" +
		"      go build -tags desktop -o ssha ./cmd/ssha\n" +
		"    或者用打包好的桌面版（deb / AppImage / exe）\n" +
		"  · 现在就要用：ssha ui --headless")
}
