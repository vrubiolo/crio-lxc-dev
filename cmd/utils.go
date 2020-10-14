package main

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

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
	log.Trace().Str("current:", currentPath).Str("sub:", subPath).Msg("resolve path relative")
	p := filepath.Join(currentPath, subPath)

	stat, err := os.Lstat(p)
	if err != nil {
		// target does not exist, resolution ends here
		return p, err
	}

	if stat.Mode()&os.ModeSymlink == 0 {
		log.Trace().Str("filepath:", p).Msg("is not a symlink")
		return p, nil
	}
	// resolve symlink

	linkDst, err := os.Readlink(p)
	if err != nil {
		return p, err
	}

	log.Trace().Str("link:", p).Str("dst:", linkDst).Msg("symlink detected")

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
	// get path entries
	entries := strings.Split(strings.TrimPrefix(dst, "/"), "/")

	currentPath := rootfs
	// start path resolution at rootfs
	for i, entry := range entries {
		currentPath, err = resolvePathRelative(rootfs, currentPath, entry)
		log.Trace().Err(err).Str("dst:", currentPath).Msg("path resolved")
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

func touchFile(filePath string, perm os.FileMode) error {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDONLY, perm)
	if err == nil {
		f.Close()
	}
	return err
}

// https://kubernetes.io/docs/setup/production-environment/container-runtimes/
// kubelet --cgroup-driver systemd --cgroups-per-qos
type CgroupPath struct {
	Slices []string
	Scope  string
}

func (cg CgroupPath) String() string {
	return filepath.Join(append(cg.Slices, cg.Scope)...)
}

// kubernetes creates the cgroup hierarchy which can be changed by serveral cgroup related flags.
// kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod87f8bc68_7c18_4a1d_af9f_54eff815f688.slice
// kubepods-burstable-pod9da3b2a14682e1fb23be3c2492753207.slice:crio:fe018d944f87b227b3b7f86226962639020e99eac8991463bf7126ef8e929589
// https://github.com/cri-o/cri-o/issues/2632
func ParseSystemdCgroupPath(s string) (cg CgroupPath) {
	if s == "" {
		return cg
	}
	parts := strings.Split(s, ":")

	slices := parts[0]
	fmt.Printf("%s", slices)
	for i, r := range slices {
		if r == '-' && i > 0 {
			slice := slices[0:i] + ".slice"
			cg.Slices = append(cg.Slices, slice)
		}
	}
	cg.Slices = append(cg.Slices, slices)
	if len(parts) > 0 {
		cg.Scope = strings.Join(parts[1:], "-") + ".scope"
	}
	return cg
}

func loadEnvDefaults(envFile string) error {
	_, err := os.Stat(envFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.Wrapf(err, "failed to stat %s", envFile)
	}
	data, err := ioutil.ReadFile(envFile)
	if err != nil {
		return errors.Wrap(err, "failed to load env file")
	}
	lines := strings.Split(string(data), "\n")
	for n, line := range lines {
		trimmed := strings.TrimSpace(line)
		//skip over comments and blank lines
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		vals := strings.SplitN(trimmed, "=", 2)
		if len(vals) != 2 {
			return fmt.Errorf("Invalid environment variable at %s +%d", envFile, n)
		}
		key := strings.TrimSpace(vals[0])
		val := strings.Trim(strings.TrimSpace(vals[1]), `"'`)
		// existing environment variables have precedence
		if _, exist := os.LookupEnv(key); !exist {
			os.Setenv(key, val)
		}
	}
	return nil
}
