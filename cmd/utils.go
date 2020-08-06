package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli"

	lxc "gopkg.in/lxc/go-lxc.v2"
)

func readBundleSpec(specFilePath string) (spec *specs.Spec, err error) {
	specFile, err := os.Open(specFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open spec file '%s'", specFilePath)
	}
	defer specFile.Close()
	err = json.NewDecoder(specFile).Decode(&spec)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode spec file")
	}

	return spec, nil
}

func configureLogging(ctx *cli.Context, c *lxc.Container) error {
	if ctx.GlobalIsSet("log-level") {
		var logLevel lxc.LogLevel
		switch strings.ToLower(ctx.GlobalString("log-level")) {
		case "trace":
			logLevel = lxc.TRACE
		case "debug":
			logLevel = lxc.DEBUG
		case "info":
			logLevel = lxc.INFO
		case "warn":
			logLevel = lxc.WARN
		case "", "error":
			logLevel = lxc.ERROR
		default:
			return fmt.Errorf("lxc driver config 'log_level' can only be trace, debug, info, warn or error")
		}
		c.SetLogLevel(logLevel)
	}

	if ctx.GlobalIsSet("log-file") {
		c.SetLogFile(ctx.GlobalString("log-file"))
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func containerExists(containerID string) (bool, error) {
	// check for container existence by looking for config file.
	// otherwise NewContainer will return an empty container
	// struct and we'll report wrong info
	configExists, err := pathExists(filepath.Join(LXC_PATH, containerID, "config"))
	if err != nil {
		return false, errors.Wrap(err, "failed to check path existence of config")
	}

	return configExists, nil
}

func RunCommand(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Errorf("%s: %s: %s", strings.Join(args, " "), err, string(output))
	}
	return nil
}

func resolveRootfsSymlinks(rootfs string, dst string) (string, error) {
	stat, err := os.Lstat(dst)
	if err != nil {
		return dst, err
	}
	if stat.Mode()&os.ModeSymlink == 0 {
		return dst, nil // not a symlink
	}
	target, err := os.Readlink(dst)
	if err != nil {
		return dst, err
	}
	if !strings.HasPrefix(target, rootfs) {
		return filepath.Join(rootfs, target), nil
	}
	return target, nil
}

// resolveMountDestination resolves mount destination paths for LXC.
//
// Symlinks in mount mount destination paths are not allowed in LXC.
// See CVE-2015-1335: Protect container mounts against symlinks
// and https://github.com/lxc/lxc/commit/592fd47a6245508b79fe6ac819fe6d3b2c1289be
// Mount targets that contain symlinks should be resolved relative to the container rootfs.
// e.g k8s service account tokens are mounted to /var/run/secrets/kubernetes.io/serviceaccount
// but /var/run is (mostly) a symlink to /run, so LXC denies to mount the serviceaccount token.
//
// The mount destination must be either relative to the container root or absolute to
// the directory on the host containing the rootfs.
// LXC simply ignores relative mounts paths to an absolute rootfs.
// See man lxc.container.conf #MOUNT POINTS
//
// The mount option `create=dir` should be set when the error os.ErrNotExist is returned.
// The non-existent directories are then automatically created by LXC.
func resolveMountDestination(rootfs string, dst string) (string, error) {
	dst = strings.TrimPrefix(dst, "/")
	entries := strings.Split(dst, "/")
	dstPath := rootfs
	for i, entry := range entries {
		dstPath = filepath.Join(dstPath, entry)
		resolved, err := resolveRootfsSymlinks(rootfs, dstPath)
		dstPath = resolved
		if err != nil {
			// The already resolved path is concatenated with the remaining path to be resolved,
			// if resolution of path fails at some point.
			return filepath.Join(dstPath, filepath.Join(entries[i+1:]...)), err
		}
	}
	return dstPath, nil
}

// createPidFile atomically creates a pid file for the given pid at the given path
func createPidFile(path string, pid int) error {
	tmpDir := filepath.Dir(path)
	tmpName := filepath.Join(tmpDir, fmt.Sprintf(".%s", filepath.Base(path)))

	f, err := os.OpenFile(tmpName, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0640)
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

// checkRuntime checks runtime requirements
// An error is returned if any runtime requirement is not met.
func checkRuntime() error {
	// TODO check in build script
	// minimal lxc version is 3.1 https://discuss.linuxcontainers.org/t/lxc-3-1-has-been-released/3527
	if ! lxc.VersionAtLeast(3, 1, 0) {
		return fmt.Errorf("LXC runtime version > 3.1.0 required, but was %s", lxc.Version())
	}
	return nil
}
