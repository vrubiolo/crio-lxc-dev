package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	ldd "github.com/u-root/u-root/pkg/ldd"
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

func parseLogLevel(s string) (lxc.LogLevel, error) {
	switch strings.ToLower(s) {
	case "trace":
		return lxc.TRACE, nil
	case "debug":
		return lxc.DEBUG, nil
	case "info":
		return lxc.INFO, nil
	case "warn":
		return lxc.WARN, nil
	case "error":
		return lxc.ERROR, nil
	default:
		return lxc.ERROR, fmt.Errorf("Invalid log-level %s", s)
	}
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

func RunCommand(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Errorf("%s: %s: %s", strings.Join(args, " "), err, string(output))
	}
	return nil
}

func resolvePathRelative(rootfs string, currentPath string, subPath string) (string, error) {
	log.Debugf("resolvePathRelative(currentPath:%s subPath:%s)", currentPath, subPath)
	p := filepath.Join(currentPath, subPath)

	stat, err := os.Lstat(p)
	if err != nil {
		// target does not exist, resolution ends here
		return p, err
	}

	if stat.Mode()&os.ModeSymlink == 0 {
		log.Debugf("%s is not a symlink", p)
		return p, nil
	}
	// resolve symlink

	linkDst, err := os.Readlink(p)
	if err != nil {
		return p, err
	}

	log.Debugf("%s -> %s", p, linkDst)

	// The destination of an absolute link must be prefixed with the rootfs
	if filepath.IsAbs(linkDst) {
		if filepath.HasPrefix(linkDst, rootfs) {
			return p, nil
		}
		return filepath.Join(rootfs, linkDst), nil
	}

	// The link target is relative to currentPath.
	return filepath.Clean(filepath.Join(currentPath, linkDst)), nil
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

// source /var/run/containers/storage/overlay-containers/51230afad17aa3b42901f6d9efcba406511821b7e18b2223a6b4c43f9327ce97/userdata/resolv.conf
// destination /etc/resolv.conf
func resolveMountDestination(rootfs string, dst string) (dstPath string, err error) {
	log.Debugf("resolveMountDestination(rootfs:%s dst:%s)", rootfs, dst)
	// get path entries
	entries := strings.Split(strings.TrimPrefix(dst, "/"), "/")

	currentPath := rootfs
	// start path resolution at rootfs
	for i, entry := range entries {
		currentPath, err = resolvePathRelative(rootfs, currentPath, entry)
		log.Debugf("resolved %s : %s", currentPath, err)
		if err != nil {
			// The already resolved path is concatenated with the remaining path,
			// if resolution of path fails at some point.
			currentPath = filepath.Join(currentPath, filepath.Join(entries[i+1:]...))
			break
		}
	}
	return currentPath, err
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
func checkRuntime(ctx *cli.Context) error {
	// TODO check in build script
	// minimal lxc version is 3.1 https://discuss.linuxcontainers.org/t/lxc-3-1-has-been-released/3527
	if !lxc.VersionAtLeast(3, 1, 0) {
		return fmt.Errorf("LXC runtime version > 3.1.0 required, but was %s", lxc.Version())
	}
	if err := isStaticBinary(ctx.String("busybox-static")); err != nil {
		return err
	}
	return nil
}

func isStaticBinary(binPath string) error {
	libs, err := ldd.Ldd([]string{binPath})
	if err != nil {
		return err
	}

	if len(libs) == 1 {
		return nil
	}
	return fmt.Errorf("%s is not a static binary", binPath)
}

// runtimeHasCapabilitySupport checks whether he given runtime binary is linked against libcap.so.
// TODO liblxc should output a better error message e.g:
// "Can not set lxc.cap.keep or lxc.cap.drop because capabilies are disabled. Please compile with --enable-capabilities"
func runtimeHasCapabilitySupport(runtime string) error {
	// assume runtime is dynamically linked
	// ldd resolves libraries recursively
	libs, err := ldd.Ldd([]string{runtime})
	if err != nil {
		return err
	}
	for _, lib := range libs {
		if strings.HasPrefix(filepath.Base(lib.FullName), "libcap.") {
			return nil
		}
	}
	return fmt.Errorf("liblxc is not linked against libcap.so")
}

type Release struct {
	Major      int
	Minor      int
	Patchlevel int
	Suffix     string
}

func (r Release) GreaterEqual(major, minor, patchlevel int) bool {
	if r.Major < major {
		return false
	}
	if r.Major > major {
		return true
	}
	if r.Minor < minor {
		return false
	}
	if r.Minor > minor {
		return true
	}
	return r.Patchlevel >= patchlevel
}

func ParseUtsnameRelease(releaseData string) (*Release, error) {
	var r Release
	numParsed, err := fmt.Sscanf(releaseData, "%d.%d.%d-%s", &r.Major, &r.Minor, &r.Patchlevel, &r.Suffix)
	if err != nil {
		if numParsed == 3 {
			return &r, nil
		}
		return nil, fmt.Errorf("Invalid format %q: %s", releaseData, err)
	}
	return &r, nil
}

func LinuxRelease() (*Release, error) {
	uts := unix.Utsname{}
	if err := unix.Uname(&uts); err != nil {
		return nil, err
	}
	zi := bytes.Index(uts.Release[:], []byte{0})
	releaseData := string(uts.Release[:zi])
	return ParseUtsnameRelease(releaseData)
}
