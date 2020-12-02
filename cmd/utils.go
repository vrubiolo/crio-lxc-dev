package main

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const undefined = -1

// createPidFile atomically creates a pid file for the given pid at the given path
func createPidFile(path string, pid int) error {
	tmpDir := filepath.Dir(path)
	tmpName := filepath.Join(tmpDir, fmt.Sprintf(".%s", filepath.Base(path)))

	// #nosec
	f, err := os.OpenFile(tmpName, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%d", pid)
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func canExecute(cmds ...string) error {
	for _, c := range cmds {
		if err := unix.Access(c, unix.X_OK); err != nil {
			return errors.Wrapf(err, "failed to access cmd %s", c)
		}
	}
	return nil
}

func filesystemName(fsName string) int64 {
	switch fsName {
	case "proc", "procfs":
		return unix.PROC_SUPER_MAGIC
	case "cgroup2", "cgroup2fs":
		return unix.CGROUP2_SUPER_MAGIC
	default:
		return undefined
	}
}

// TODO check whether dir is the filsystem root (use /proc/mounts)
func isFilesystem(dir string, fsName string) error {
	fsType := filesystemName(fsName)
	if fsType == undefined {
		return fmt.Errorf("undefined filesystem %q", fsName)
	}

	var stat unix.Statfs_t
	err := unix.Statfs(dir, &stat)
	if err != nil {
		return errors.Wrapf(err, "fstat failed for directory %s", dir)
	}
	if stat.Type != fsType {
		return fmt.Errorf("%s is not on %q filesystem", dir, fsName)
	}
	return nil
}

func parseSignal(sig string) unix.Signal {
	if sig == "" {
		return unix.SIGTERM
	}
	// handle numerical signal value
	if num, err := strconv.Atoi(sig); err == nil {
		return unix.Signal(num)
	}

	// gracefully handle all string variants e.g 'sigkill|SIGKILL|kill|KILL'
	s := strings.ToUpper(sig)
	if !strings.HasPrefix(s, "SIG") {
		s = "SIG" + s
	}
	return unix.SignalNum(s)
}
