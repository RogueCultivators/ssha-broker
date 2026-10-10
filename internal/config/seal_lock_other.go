//go:build !unix

package config

import "os"

// lockFile is a no-op where flock is unavailable. The in-process mutex still
// serializes writers inside one ssha process.
func lockFile(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }
