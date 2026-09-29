//go:build !unix

package audit

import "os"

// lockFile is a no-op on platforms without flock; the in-process mutex still
// serializes writers within a single ssha process.
func lockFile(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }
