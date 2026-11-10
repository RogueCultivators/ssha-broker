package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// backupPrefix is appended to the config file name for timestamped copies.
const backupPrefix = ".bak-"

// backupKeep is how many timestamped copies survive a save. Ten saves is
// enough to undo a bad afternoon, and old copies of a file that holds no
// secrets are cheap.
const backupKeep = 10

// backupLayout sorts lexically and reads back into a time. UTC keeps the order
// stable when the machine changes time zone or a DST fallback repeats an hour.
const backupLayout = "20060102-150405.000000000"

// Backup is one timestamped copy of the config file.
type Backup struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	ModTime time.Time `json:"mod_time"`
	Size    int64     `json:"size"`
}

// rotateBackup writes data as a timestamped copy next to path, refreshes the
// single .bak file, and drops all but the newest backupKeep timestamped copies.
// Failures are deliberately ignored: a backup is a convenience, and it must
// never turn a save that already succeeded into an error.
func rotateBackup(path string, data []byte, mode os.FileMode) {
	if len(data) == 0 {
		return
	}
	_ = os.WriteFile(path+".bak", data, mode)
	stamp := path + backupPrefix + time.Now().UTC().Format(backupLayout)
	name := stamp
	for i := 1; ; i++ {
		if _, err := os.Stat(name); os.IsNotExist(err) {
			break
		}
		name = stamp + fmt.Sprintf("-%d", i)
	}
	if err := os.WriteFile(name, data, mode); err != nil {
		return
	}
	old, err := Backups(path)
	if err != nil {
		return
	}
	for i := backupKeep; i < len(old); i++ {
		_ = os.Remove(old[i].Path)
	}
}

// Backups lists the timestamped copies of path, newest first. A .bak file
// without a timestamp is not part of the rotation and stays out of the list.
func Backups(path string) ([]Backup, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	prefix := base + backupPrefix
	var out []Backup
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Backup{
			Name:    e.Name(),
			Path:    filepath.Join(dir, e.Name()),
			ModTime: info.ModTime(),
			Size:    info.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		ni, nj := out[i].Name, out[j].Name
		if ni != nj {
			return ni > nj
		}
		return out[i].ModTime.After(out[j].ModTime)
	})
	return out, nil
}

// RestoreBackup validates name as one of path's timestamped copies and makes it
// the config file again. The current file is copied to the rotation first, so a
// restore is itself undoable; the returned name is that safety copy. Nothing is
// touched when the backup does not parse as a config.
func RestoreBackup(path, name string) (string, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	if name != filepath.Base(name) || !strings.HasPrefix(name, base+backupPrefix) {
		return "", fmt.Errorf("不是这个配置文件的备份：%q", name)
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}

	mode := os.FileMode(0o600)
	var current []byte
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
		if b, err := os.ReadFile(path); err == nil {
			current = b
		}
	}
	if err := validateConfigBytes(dir, data); err != nil {
		return "", fmt.Errorf("备份 %s 无法作为配置读取：%w", name, err)
	}

	saved := ""
	if len(current) > 0 && !bytes.Equal(current, data) {
		rotateBackup(path, current, mode)
		if list, err := Backups(path); err == nil && len(list) > 0 {
			saved = list[0].Name
		}
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return "", err
	}
	return saved, nil
}

// validateConfigBytes loads data from a temporary file in the same directory,
// so relative paths resolve the way they will after the restore.
func validateConfigBytes(dir string, data []byte) error {
	f, err := os.CreateTemp(dir, ".ssha-restore-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = Load(name)
	return err
}
