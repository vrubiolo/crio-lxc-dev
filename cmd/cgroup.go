package main

import (
	"fmt"
	"path/filepath"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	lxc "gopkg.in/lxc/go-lxc.v2"
)

// https://github.com/opencontainers/runtime-spec/blob/v1.0.2/config-linux.md
// TODO New spec will contain a property Unified for cgroupv2 properties
// https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md#unified
func configureCgroupResources(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	linux := spec.Linux

	if linux.CgroupsPath != "" {
		if clxc.SystemdCgroup {
			cgPath := ParseSystemdCgroupPath(linux.CgroupsPath)
			// @since lxc @a900cbaf257c6a7ee9aa73b09c6d3397581d38fb
			// checking for on of the config items shuld be enough, because they were introduced together ...
			if lxc.IsSupportedConfigItem("lxc.cgroup.dir.container") && lxc.IsSupportedConfigItem("lxc.cgroup.dir.monitor") {
				if err := clxc.SetConfigItem("lxc.cgroup.dir.container", cgPath.String()); err != nil {
					return err
				}
				if err := clxc.SetConfigItem("lxc.cgroup.dir.monitor", filepath.Join(clxc.MonitorCgroup, c.Name()+".scope")); err != nil {
					return err
				}
			} else {
				if err := clxc.SetConfigItem("lxc.cgroup.dir", cgPath.String()); err != nil {
					return err
				}
			}
		} else {
			if err := clxc.SetConfigItem("lxc.cgroup.dir", linux.CgroupsPath); err != nil {
				return err
			}
		}
	}

	// lxc.cgroup.root and lxc.cgroup.relative must not be set for cgroup v2
	if err := clxc.SetConfigItem("lxc.cgroup.relative", "0"); err != nil {
		return err
	}

	if err := configureCgroupDevices(spec); err != nil {
		return err
	}

	// Memory restriction configuration
	if mem := linux.Resources.Memory; mem != nil {
		log.Debug().Msg("TODO configure cgroup memory controller")
	}
	// CPU resource restriction configuration
	if cpu := linux.Resources.CPU; cpu != nil {
		// use strconv.FormatUint(n, 10) instead of fmt.Sprintf ?
		log.Debug().Msg("TODO configure cgroup cpu controller")
		/*
			if cpu.Shares != nil && *cpu.Shares > 0 {
					if err := clxc.SetConfigItem("lxc.cgroup2.cpu.shares", fmt.Sprintf("%d", *cpu.Shares)); err != nil {
						return err
					}
			}
			if cpu.Quota != nil && *cpu.Quota > 0 {
				if err := clxc.SetConfigItem("lxc.cgroup2.cpu.cfs_quota_us", fmt.Sprintf("%d", *cpu.Quota)); err != nil {
					return err
				}
			}
				if cpu.Period != nil && *cpu.Period != 0 {
					if err := clxc.SetConfigItem("lxc.cgroup2.cpu.cfs_period_us", fmt.Sprintf("%d", *cpu.Period)); err != nil {
						return err
					}
				}
			if cpu.Cpus != "" {
				if err := clxc.SetConfigItem("lxc.cgroup2.cpuset.cpus", cpu.Cpus); err != nil {
					return err
				}
			}
			if cpu.RealtimePeriod != nil && *cpu.RealtimePeriod > 0 {
				if err := clxc.SetConfigItem("lxc.cgroup2.cpu.rt_period_us", fmt.Sprintf("%d", *cpu.RealtimePeriod)); err != nil {
					return err
				}
			}
			if cpu.RealtimeRuntime != nil && *cpu.RealtimeRuntime > 0 {
				if err := clxc.SetConfigItem("lxc.cgroup2.cpu.rt_runtime_us", fmt.Sprintf("%d", *cpu.RealtimeRuntime)); err != nil {
					return err
				}
			}
		*/
		// Mems string `json:"mems,omitempty"`
	}

	// Task resource restriction configuration.
	if pids := linux.Resources.Pids; pids != nil {
		if err := clxc.SetConfigItem("lxc.cgroup2.pids.max", fmt.Sprintf("%d", pids.Limit)); err != nil {
			return err
		}
	}
	// BlockIO restriction configuration
	if blockio := linux.Resources.BlockIO; blockio != nil {
		log.Debug().Msg("TODO configure cgroup blockio controller")
	}
	// Hugetlb limit (in bytes)
	if hugetlb := linux.Resources.HugepageLimits; hugetlb != nil {
		log.Debug().Msg("TODO configure cgroup hugetlb controller")
	}
	// Network restriction configuration
	if net := linux.Resources.Network; net != nil {
		log.Debug().Msg("TODO configure cgroup network controllers")
	}
	return nil
}

func configureCgroupDevices(spec *specs.Spec) error {
	if err := ensureDefaultDevices(spec); err != nil {
		return errors.Wrapf(err, "failed to add default devices")
	}

	devicesAllow := "lxc.cgroup2.devices.allow"
	devicesDeny := "lxc.cgroup2.devices.deny"

	if !clxc.CgroupDevices {
		// allow read-write-mknod access to all char and block devices
		if err := clxc.SetConfigItem(devicesAllow, "b *:* rwm"); err != nil {
			return err
		}
		if err := clxc.SetConfigItem(devicesAllow, "c *:* rwm"); err != nil {
			return err
		}
		return nil
	}

	// Set cgroup device permissions from spec.
	// Device rule parsing in LXC is not well documented in lxc.container.conf
	// see https://github.com/lxc/lxc/blob/79c66a2af36ee8e967c5260428f8cdb5c82efa94/src/lxc/cgroups/cgfsng.c#L2545
	// Mixing allow/deny is not permitted by lxc.cgroup2.devices.
	// Best practise is to build up an allow list to disable access restrict access to new/unhandled devices.

	anyDevice := ""
	blockDevice := "b"
	charDevice := "c"

	for _, dev := range spec.Linux.Resources.Devices {
		key := devicesDeny
		if dev.Allow {
			key = devicesAllow
		}

		maj := "*"
		if dev.Major != nil {
			maj = fmt.Sprintf("%d", *dev.Major)
		}

		min := "*"
		if dev.Minor != nil {
			min = fmt.Sprintf("%d", *dev.Minor)
		}

		switch dev.Type {
		case anyDevice:
			// do not deny any device, this will also deny access to default devices
			if !dev.Allow {
				continue
			}
			// decompose
			val := fmt.Sprintf("%s %s:%s %s", blockDevice, maj, min, dev.Access)
			if err := clxc.SetConfigItem(key, val); err != nil {
				return err
			}
			val = fmt.Sprintf("%s %s:%s %s", charDevice, maj, min, dev.Access)
			if err := clxc.SetConfigItem(key, val); err != nil {
				return err
			}
		case blockDevice, charDevice:
			val := fmt.Sprintf("%s %s:%s %s", dev.Type, maj, min, dev.Access)
			if err := clxc.SetConfigItem(key, val); err != nil {
				return err
			}
		default:
			return fmt.Errorf("Invalid cgroup2 device - invalid type (allow:%t %s %s:%s %s)", dev.Allow, dev.Type, maj, min, dev.Access)
		}
	}
	return nil
}

