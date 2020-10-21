package main

import (
	"bytes"
	"fmt"
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

// TODO This should be added to the urfave/cli API - create a pull request
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

func nullTerminatedString(data []byte) string {
	i := bytes.Index(data, []byte{0})
	return string(data[:i])
}
