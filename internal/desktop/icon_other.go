//go:build desktop && !linux

package desktop

// setWindowIcon is a no-op where the icon comes from the bundle or the exe
// resource rather than the icon theme.
func setWindowIcon() {}
