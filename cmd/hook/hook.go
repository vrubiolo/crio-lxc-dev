package main

import (
	"fmt"
	"github.com/lxc/crio-lxc/clxc"
	"os"
	"path/filepath"
)

func fail(err error, details string) {
	msg := fmt.Errorf("ERR: %s failed: %s", details, err.Error())
	panic(msg)
}

func main() {
	// get rootfs mountpoint from environment
	rootfs := os.Getenv("LXC_ROOTFS_MOUNT")
	if rootfs == "" {
		panic("LXC_ROOTFS_MOUNT environment is not set")
	}

	if _, err := os.Stat(rootfs); err != nil {
		fail(err, "stat for rootfs mount failed "+rootfs)
	}

	specPath := filepath.Join(rootfs, clxc.INIT_SPEC)
	spec, err := clxc.ReadSpec(specPath)
	if err != nil {
		fail(err, "parse spec "+specPath)
	}

	for _, dev := range spec.Linux.Devices {
		dev.Path = filepath.Join(rootfs, dev.Path)
		if err := clxc.CreateDevice(spec, dev); err != nil {
			fail(err, "failed to create device "+dev.Path)
		}
	}

	for _, p := range spec.Linux.MaskedPaths {
		rp := filepath.Join(rootfs, p)
		if err := clxc.MaskPath(rp); err != nil {
			fail(err, "failed to mask path "+rp)
		}
	}
}
