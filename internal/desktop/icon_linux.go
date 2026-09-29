//go:build desktop && linux

package desktop

/*
#cgo pkg-config: gtk+-3.0
#include <gtk/gtk.h>

static void ssha_set_default_icon(const char *name) {
	gtk_window_set_default_icon_name(name);
}
*/
import "C"

import "unsafe"

// setWindowIcon asks GTK for the theme icon called "ssha", which is the name the
// Linux packages install. Without it the window has no _NET_WM_ICON and a
// taskbar may show a generic placeholder. Must run before the window is created.
func setWindowIcon() {
	name := C.CString("ssha")
	defer C.free(unsafe.Pointer(name))
	C.ssha_set_default_icon(name)
}
