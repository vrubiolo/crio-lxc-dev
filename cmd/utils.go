package main

import (
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	//	"os"
	//	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const undefined = -1

func readPidFile(path string) (int, error) {
	// #nosec
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	return strconv.Atoi(s)
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
