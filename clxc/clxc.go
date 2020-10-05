package clxc

import (
	// consider an alternative json parser
	// e.g https://github.com/buger/jsonparser
	//"github.com/pkg/json" // adds about 200k
	"encoding/json" // adds about 400k
	"fmt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

const (
	// CFG_DIR is bind mounted (readonly) to container
	CFG_DIR           = "/.crio-lxc"
	SYNC_FIFO         = "/syncfifo"
	SYNC_FIFO_PATH    = CFG_DIR + SYNC_FIFO
	SYNC_FIFO_CONTENT = "meshuggah rocks"
	INIT_CMD          = CFG_DIR + "/init"
	INIT_SPEC         = CFG_DIR + "/spec.json"
)

func ReadSpec(specFilePath string) (*specs.Spec, error) {
	specFile, err := os.Open(specFilePath)
	if err != nil {
		return nil, err
	}
	defer specFile.Close()
	spec := &specs.Spec{}
	err = json.NewDecoder(specFile).Decode(spec)
	if err != nil {
		return nil, err
	}
	return spec, nil
}

func WriteSpec(spec *specs.Spec, specFilePath string) error {
	f, err := os.OpenFile(specFilePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0555)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(spec)
}

func HasCapability(spec *specs.Spec, capName string) bool {
	if capName == "" {
		return false
	}
	if spec.Process.Capabilities == nil {
		return false
	}

	for _, c := range spec.Process.Capabilities.Permitted {
		if strings.ToLower(capName) == strings.ToLower(c) {
			return true
		}
	}
	return false

}

func getType(s string) int {
	switch s {
	case "b":
		return unix.S_IFBLK
	case "c":
		return unix.S_IFCHR
	case "p":
		return unix.S_IFIFO
		// case "u": ? unbuffered character device ?
	}
	return -1
}

func CreateDevices(spec *specs.Spec) error {
	for _, dev := range spec.Linux.Devices {
		err := CreateDevice(spec, dev)
		if err != nil {
			return fmt.Errorf("failed to create device %s: %s", dev.Path, err)
		}
	}
	return nil
}

func CreateDevice(spec *specs.Spec, dev specs.LinuxDevice) error {
	var mode uint32 = 0660
	if dev.FileMode != nil {
		mode |= uint32(*dev.FileMode)
	}
	devType := getType(dev.Type)
	if devType == -1 {
		return fmt.Errorf("unsupported device type: %s", dev.Type)
	}
	mode |= uint32(devType)

	devMode := 0
	if devType == unix.S_IFBLK || devType == unix.S_IFCHR {
		devMode = int(unix.Mkdev(uint32(dev.Major), uint32(dev.Minor)))
	}

	os.MkdirAll(filepath.Dir(dev.Path), 0755)

	err := unix.Mknod(dev.Path, mode, devMode)
	if err != nil {
		return fmt.Errorf("mknod failed: %s", err)
	}

	uid := spec.Process.User.UID
	if dev.UID != nil {
		uid = *dev.UID
	}
	gid := spec.Process.User.GID
	if dev.GID != nil {
		gid = *dev.GID
	}
	err = unix.Chown(dev.Path, int(uid), int(gid))
	if err != nil {
		return fmt.Errorf("chown failed: %s", err)
	}
	return nil
}

func MaskPath(p string) error {
	err := unix.Mount("/dev/null", p, "", unix.MS_BIND, "")
	if os.IsNotExist(err) {
		return nil
	}
	if err == unix.ENOTDIR {
		return unix.Mount("tmpfs", p, "tmpfs", unix.MS_RDONLY, "")
	}
	return err
}
