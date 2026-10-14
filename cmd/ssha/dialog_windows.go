//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// reportFatal shows a message box. The window build is a GUI process with no
// console, so this is the only way the operator learns why it would not start.
func reportFatal(msg string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBox := user32.NewProc("MessageBoxW")

	text, err := syscall.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	title, err := syscall.UTF16PtrFromString("ssha")
	if err != nil {
		return
	}
	const mbIconError = 0x00000010
	_, _, _ = messageBox.Call(0,
		uintptr(unsafe.Pointer(text)),
		uintptr(unsafe.Pointer(title)),
		mbIconError)
}
