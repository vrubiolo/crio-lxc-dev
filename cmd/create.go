package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/creack/pty"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	api "github.com/lxc/crio-lxc/clxc"
	lxc "gopkg.in/lxc/go-lxc.v2"
)

var createCmd = cli.Command{
	Name:      "create",
	Usage:     "create a container from a bundle directory",
	ArgsUsage: "<containerID>",
	Action:    doCreate,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:        "bundle",
			Usage:       "set bundle directory",
			Value:       ".",
			Destination: &clxc.BundlePath,
		},
		&cli.StringFlag{
			Name:  "console-socket",
			Usage: "send container pty master fd to this socket path",
		},
		&cli.StringFlag{
			Name:  "pid-file",
			Usage: "path to write container PID",
		},
		&cli.DurationFlag{
			Name:    "timeout",
			Usage:   "timeout for container creation",
			EnvVars: []string{"CRIO_LXC_CREATE_TIMEOUT"},
			Value:   time.Second * 5,
		},
	},
}

type Namespace struct {
	Name      string
	CloneFlag int
}

// maps from CRIO namespace names to LXC names and clone flags
var NamespaceMap = map[specs.LinuxNamespaceType]Namespace{
	specs.CgroupNamespace:  Namespace{"cgroup", unix.CLONE_NEWCGROUP},
	specs.IPCNamespace:     Namespace{"ipc", unix.CLONE_NEWIPC},
	specs.MountNamespace:   Namespace{"mnt", unix.CLONE_NEWNS},
	specs.NetworkNamespace: Namespace{"net", unix.CLONE_NEWNET},
	specs.PIDNamespace:     Namespace{"pid", unix.CLONE_NEWPID},
	specs.UserNamespace:    Namespace{"user", unix.CLONE_NEWUSER},
	specs.UTSNamespace:     Namespace{"uts", unix.CLONE_NEWUTS},
}

func createInitSpec(spec *specs.Spec) error {
	err := RunCommand("mkdir", "-p", "-m", "0755", filepath.Join(spec.Root.Path, api.CFG_DIR))
	if err != nil {
		return errors.Wrapf(err, "Failed creating %s in rootfs", api.CFG_DIR)
	}
	err = RunCommand("mkdir", "-p", "-m", "0755", clxc.RuntimePath(api.CFG_DIR))
	if err != nil {
		return errors.Wrapf(err, "Failed creating %s in lxc container dir", api.CFG_DIR)
	}

	// create named fifo in lxcpath and mount it into the container
	if err := makeSyncFifo(clxc.RuntimePath(api.SYNC_FIFO_PATH)); err != nil {
		return errors.Wrapf(err, "failed to make sync fifo")
	}

	spec.Mounts = append(spec.Mounts, specs.Mount{
		Source:      clxc.RuntimePath(api.CFG_DIR),
		Destination: strings.Trim(api.CFG_DIR, "/"),
		Type:        "bind",
		Options:     []string{"bind", "ro"},
	})

	if err := clxc.SetConfigItem("lxc.hook.mount", clxc.HookCommand); err != nil {
		return err
	}

	path := "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, kv := range spec.Process.Env {
		if strings.HasPrefix(kv, "PATH=") {
			path = kv
		}
	}
	if err := clxc.SetConfigItem("lxc.environment", path); err != nil {
		return err
	}

	if err := clxc.SetConfigItem("lxc.environment", envStateCreated); err != nil {
		return err
	}

	// create destination file for bind mount
	initBin := clxc.RuntimePath(api.INIT_CMD)
	err = touchFile(initBin, 0750)
	if err != nil {
		return errors.Wrapf(err, "failed to create %s", initBin)
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Source:      clxc.InitCommand,
		Destination: api.INIT_CMD,
		Type:        "bind",
		Options:     []string{"bind", "ro"},
	})
	return clxc.SetConfigItem("lxc.init.cmd", api.INIT_CMD)
}

func configureNamespaces(c *lxc.Container, spec *specs.Spec) error {
	procPidPathRE := regexp.MustCompile(`/proc/(\d+)/ns`)

	var configVal string
	seenNamespaceTypes := map[specs.LinuxNamespaceType]bool{}
	for _, ns := range spec.Linux.Namespaces {
		if _, ok := seenNamespaceTypes[ns.Type]; ok {
			return fmt.Errorf("duplicate namespace type %s", ns.Type)
		}
		seenNamespaceTypes[ns.Type] = true
		if ns.Path == "" {
			continue
		}

		n, supported := NamespaceMap[ns.Type]
		if !supported {
			return fmt.Errorf("Unsupported namespace %s", ns.Type)
		}
		configKey := fmt.Sprintf("lxc.namespace.share.%s", n.Name)

		matches := procPidPathRE.FindStringSubmatch(ns.Path)
		switch len(matches) {
		case 0:
			configVal = ns.Path
		case 1:
			return fmt.Errorf("error parsing namespace path. expected /proc/(\\d+)/ns/*, got '%s'", ns.Path)
		case 2:
			configVal = matches[1]
		default:
			return fmt.Errorf("error parsing namespace path. expected /proc/(\\d+)/ns/*, got '%s'", ns.Path)
		}

		if err := clxc.SetConfigItem(configKey, configVal); err != nil {
			return err
		}
	}

	// Note  that  if the container requests a new user namespace and the container wants to in‐
	// herit the network namespace it needs to inherit the user namespace as well.
	if !seenNamespaceTypes[specs.NetworkNamespace] && seenNamespaceTypes[specs.UserNamespace] {
		return fmt.Errorf("to inherit the network namespace the user namespace must be inherited as well")
	}

	nsToKeep := make([]string, 0, len(NamespaceMap))
	for key, n := range NamespaceMap {
		if !seenNamespaceTypes[key] {
			nsToKeep = append(nsToKeep, n.Name)
		}
	}
	if err := clxc.SetConfigItem("lxc.namespace.keep", strings.Join(nsToKeep, " ")); err != nil {
		return err
	}

	return nil
}

func doCreate(ctx *cli.Context) error {
	err := doCreateInternal(ctx)
	if clxc.Backup || (err != nil && clxc.BackupOnError) {
		backupDir, backupErr := clxc.BackupRuntimeResources()
		if backupErr == nil {
			log.Warn().Str("dir:", backupDir).Msg("runtime backup completed")
		} else {
			log.Error().Err(backupErr).Str("dir:", backupDir).Msg("runtime backup failed")
		}
	}
	return err
}

func doCreateInternal(ctx *cli.Context) error {
	// minimal lxc version is 3.1 https://discuss.linuxcontainers.org/t/lxc-3-1-has-been-released/3527
	if !lxc.VersionAtLeast(3, 1, 0) {
		return fmt.Errorf("LXC runtime version > 3.1.0 required, but was %s", lxc.Version())
	}

	err := clxc.LoadContainer()
	if err == nil {
		return fmt.Errorf("container already exists")
	}

	err = clxc.CreateContainer()
	if err != nil {
		return errors.Wrap(err, "failed to create container")
	}
	c := clxc.Container

	if err := clxc.SetConfigItem("lxc.log.file", clxc.LogFilePath); err != nil {
		return err
	}

	err = c.SetLogLevel(clxc.LogLevel)
	if err != nil {
		return errors.Wrap(err, "failed to set container loglevel")
	}
	if clxc.LogLevel == lxc.TRACE {
		c.SetVerbosity(lxc.Verbose)
	}

	clxc.SpecPath = filepath.Join(clxc.BundlePath, "config.json")
	spec, err := api.ReadSpec(clxc.SpecPath)
	if err != nil {
		return errors.Wrap(err, "couldn't load bundle spec")
	}

	if err := configureContainer(ctx, c, spec); err != nil {
		return errors.Wrap(err, "failed to configure container")
	}

	return startContainer(ctx, c, spec, ctx.Duration("timeout"))
}

var seccompAction = map[specs.LinuxSeccompAction]string{
	specs.ActKill:  "kill",
	specs.ActTrap:  "trap",
	specs.ActErrno: "errno",
	specs.ActAllow: "allow",
	//specs.ActTrace: "trace",
	//specs.ActLog: "log",
	//specs.ActKillProcess: "kill_process",
}

func writeSeccompSyscall(w *bufio.Writer, sc specs.LinuxSyscall) error {
	for _, name := range sc.Names {
		action, ok := seccompAction[sc.Action]
		if !ok {
			return fmt.Errorf("unsupported seccomp action: %s", sc.Action)
		}
		if len(sc.Args) == 0 {
			fmt.Fprintf(w, "%s %s\n", name, action)
		} else {
			// Only write a single argument per line - this is required when the same arg.Index is used multiple times.
			// from `man 7 seccomp_rule_add_exact_array`
			// "When adding syscall argument comparisons to the filter it is important to remember
			// that while it is possible to have multiple comparisons in a single rule,
			// you can only compare each argument once in a single rule.
			// In other words, you can not have multiple comparisons of the 3rd syscall argument in a single rule."
			for _, arg := range sc.Args {
				fmt.Fprintf(w, "%s %s [%d,%d,%s,%d]\n", name, action, arg.Index, arg.Value, arg.Op, arg.ValueTwo)
			}
		}
	}
	return nil
}

func defaultAction(seccomp *specs.LinuxSeccomp) (string, error) {
	switch seccomp.DefaultAction {
	case specs.ActKill:
		return "kill", nil
	case specs.ActTrap:
		return "trap", nil
	case specs.ActErrno:
		return "errno 0", nil
	case specs.ActAllow:
		return "allow", nil
	case specs.ActTrace, specs.ActLog: // Not (yet) supported by lxc
		log.Warn().Str("action:", string(seccomp.DefaultAction)).Msg("unsupported seccomp default action")
		fallthrough
	//case specs.ActKillProcess: fallthrough // specs > 1.0.2
	default:
		return "kill", fmt.Errorf("Unsupported seccomp default action %q", seccomp.DefaultAction)
	}
}

func seccompArchs(seccomp *specs.LinuxSeccomp) ([]string, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return nil, err
	}
	nativeArch := nullTerminatedString(uts.Machine[:])
	archs := make([]string, len(seccomp.Architectures))
	for _, a := range seccomp.Architectures {
		s := strings.ToLower(strings.TrimLeft(string(a), "SCMP_ARCH_"))
		if strings.ToLower(nativeArch) == s {
			// lxc seccomp code automatically adds syscalls to compat architectures
			return []string{nativeArch}, nil
		}
		archs = append(archs, s)
	}
	return archs, nil
}

func writeSeccompProfile(profilePath string, seccomp *specs.LinuxSeccomp) error {
	profile, err := os.OpenFile(profilePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0440)
	if err != nil {
		return err
	}
	defer profile.Close()

	w := bufio.NewWriter(profile)
	defer w.Flush()

	w.WriteString("2\n")
	action, err := defaultAction(seccomp)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "allowlist %s\n", action)

	platformArchs, err := seccompArchs(seccomp)
	if err != nil {
		return errors.Wrap(err, "Failed to detect platform architecture")
	}
	log.Debug().Str("action:", action).Strs("archs:", platformArchs).Msg("create seccomp profile")
	for _, arch := range platformArchs {
		fmt.Fprintf(w, "[%s]\n", arch)
		for _, sc := range seccomp.Syscalls {
			if err := writeSeccompSyscall(w, sc); err != nil {
				return err
			}
		}
	}
	return nil
}

func configureSeccomp(c *lxc.Container, spec *specs.Spec) error {
	if !clxc.Seccomp {
		return nil
	}

	if spec.Linux.Seccomp == nil || len(spec.Linux.Seccomp.Syscalls) == 0 {
		return nil
	}

	// TODO warn if seccomp is not available in liblxc

	if spec.Process.NoNewPrivileges {
		if err := clxc.SetConfigItem("lxc.no_new_privs", "1"); err != nil {
			return err
		}
	}

	profilePath := clxc.RuntimePath("seccomp.conf")
	if err := writeSeccompProfile(profilePath, spec.Linux.Seccomp); err != nil {
		return err
	}

	return clxc.SetConfigItem("lxc.seccomp.profile", profilePath)
}

func configureApparmor(c *lxc.Container, spec *specs.Spec) error {
	if !clxc.Apparmor {
		return nil
	}
	// The value *apparmor_profile*  from crio.conf is used if no profile is defined by the container.
	aaprofile := spec.Process.ApparmorProfile
	if aaprofile == "" {
		aaprofile = "unconfined"
	}
	return clxc.SetConfigItem("lxc.apparmor.profile", aaprofile)
}

func configureContainerSecurity(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	if spec.Process.OOMScoreAdj != nil {
		if err := clxc.SetConfigItem("lxc.proc.oom_score_adj", fmt.Sprintf("%d", *spec.Process.OOMScoreAdj)); err != nil {
			return err
		}
	}

	if err := configureApparmor(c, spec); err != nil {
		return err
	}

	if err := configureSeccomp(c, spec); err != nil {
		return err
	}

	// Do not set "lxc.ephemeral=1" since resources not created by
	// the container runtime MUST NOT be deleted by the container runtime.
	if err := clxc.SetConfigItem("lxc.ephemeral", "0"); err != nil {
		return err
	}

	if err := configureCapabilities(ctx, c, spec); err != nil {
		return errors.Wrapf(err, "failed to configure capabilities")
	}

	if err := clxc.SetConfigItem("lxc.init.uid", fmt.Sprintf("%d", spec.Process.User.UID)); err != nil {
		return err
	}
	if err := clxc.SetConfigItem("lxc.init.gid", fmt.Sprintf("%d", spec.Process.User.GID)); err != nil {
		return err
	}

	// See `man lxc.container.conf` lxc.idmap.
	for _, m := range spec.Linux.UIDMappings {
		if err := clxc.SetConfigItem("lxc.idmap", fmt.Sprintf("u %d %d %d", m.ContainerID, m.HostID, m.Size)); err != nil {
			return err
		}
	}

	for _, m := range spec.Linux.GIDMappings {
		if err := clxc.SetConfigItem("lxc.idmap", fmt.Sprintf("g %d %d %d", m.ContainerID, m.HostID, m.Size)); err != nil {
			return err
		}
	}

	return configureCgroupResources(ctx, c, spec)
}

// configureCapabilities configures the linux capabilities / privileges granted to the container processes.
// See `man lxc.container.conf` lxc.cap.drop and lxc.cap.keep for details.
// https://blog.container-solutions.com/linux-capabilities-in-practice
// https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work
func configureCapabilities(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	if !clxc.Capabilities {
		return nil
	}

	keepCaps := "none"
	if spec.Process.Capabilities != nil {
		var caps []string
		for _, c := range spec.Process.Capabilities.Permitted {
			lcCapName := strings.TrimPrefix(strings.ToLower(c), "cap_")
			caps = append(caps, lcCapName)
		}
		keepCaps = strings.Join(caps, " ")
	}

	return clxc.SetConfigItem("lxc.cap.keep", keepCaps)
}

func isDeviceEnabled(spec *specs.Spec, dev specs.LinuxDevice) bool {
	for _, specDev := range spec.Linux.Devices {
		if specDev.Path == dev.Path {
			return true
		}
	}
	return false
}

func addDevice(spec *specs.Spec, dev specs.LinuxDevice, mode os.FileMode, uid uint32, gid uint32, access string) {
	dev.FileMode = &mode
	dev.UID = &uid
	dev.GID = &gid
	spec.Linux.Devices = append(spec.Linux.Devices, dev)

	addDevicePerms(spec, dev.Type, &dev.Major, &dev.Minor, access)
}

func addDevicePerms(spec *specs.Spec, devType string, major *int64, minor *int64, access string) {
	devCgroup := specs.LinuxDeviceCgroup{Allow: true, Type: devType, Major: major, Minor: minor, Access: access}
	spec.Linux.Resources.Devices = append(spec.Linux.Resources.Devices, devCgroup)
}

// ensureDefaultDevices adds the mandatory devices defined by the [runtime spec](https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md#default-devices)
// to the given container spec if required.
// crio can add devices to containers, but this does not work for privileged containers.
// See https://github.com/cri-o/cri-o/blob/a705db4c6d04d7c14a4d59170a0ebb4b30850675/server/container_create_linux.go#L45
// TODO file an issue on cri-o (at least for support)
func ensureDefaultDevices(spec *specs.Spec) error {
	// make sure autodev is disabled
	if err := clxc.SetConfigItem("lxc.autodev", "0"); err != nil {
		return err
	}

	mode := os.FileMode(0666)
	var uid, gid uint32 = spec.Process.User.UID, spec.Process.User.GID

	devices := []specs.LinuxDevice{
		specs.LinuxDevice{Path: "/dev/null", Type: "c", Major: 1, Minor: 3},
		specs.LinuxDevice{Path: "/dev/zero", Type: "c", Major: 1, Minor: 5},
		specs.LinuxDevice{Path: "/dev/full", Type: "c", Major: 1, Minor: 7},
		specs.LinuxDevice{Path: "/dev/random", Type: "c", Major: 1, Minor: 8},
		specs.LinuxDevice{Path: "/dev/urandom", Type: "c", Major: 1, Minor: 9},
		specs.LinuxDevice{Path: "/dev/tty", Type: "c", Major: 5, Minor: 0},
		// FIXME runtime mandates that /dev/ptmx should be bind mount from host - why ?
		// `man 2 mount` | devpts
		// ` To use this option effectively, /dev/ptmx must be a symbolic link to pts/ptmx.
		// See Documentation/filesystems/devpts.txt in the Linux kernel source tree for details.`
	}

	ptmx := specs.LinuxDevice{Path: "/dev/ptmx", Type: "c", Major: 5, Minor: 2}
	addDevicePerms(spec, "c", &ptmx.Major, &ptmx.Minor, "rwm") // /dev/ptmx, /dev/pts/ptmx

	pts0 := specs.LinuxDevice{Path: "/dev/pts/0", Type: "c", Major: 88, Minor: 0}
	addDevicePerms(spec, "c", &pts0.Major, nil, "rwm") // dev/pts/[0..9]

	// add missing default devices
	for _, dev := range devices {
		if !isDeviceEnabled(spec, dev) {
			addDevice(spec, dev, mode, uid, gid, "rwm")
		}
	}
	return nil
}

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

func isNamespaceEnabled(spec *specs.Spec, nsType specs.LinuxNamespaceType) bool {
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == nsType {
			return true
		}
	}
	return false
}

func configureContainer(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	if ctx.Bool("debug") {
		c.SetVerbosity(lxc.Verbose)
	}

	if err := clxc.SetConfigItem("lxc.rootfs.path", spec.Root.Path); err != nil {
		return err
	}

	if err := clxc.SetConfigItem("lxc.rootfs.managed", "0"); err != nil {
		return err
	}

	rootfsOptions := []string{}
	if spec.Linux.RootfsPropagation != "" {
		rootfsOptions = append(rootfsOptions, spec.Linux.RootfsPropagation)
	}
	if spec.Root.Readonly {
		rootfsOptions = append(rootfsOptions, "ro")
	}
	if err := clxc.SetConfigItem("lxc.rootfs.options", strings.Join(rootfsOptions, ",")); err != nil {
		return err
	}

	// write init spec
	if err := createInitSpec(spec); err != nil {
		return err
	}

	// excplicitly disable auto-mounting
	if err := clxc.SetConfigItem("lxc.mount.auto", ""); err != nil {
		return err
	}

	for _, ms := range spec.Mounts {
		if ms.Type == "cgroup" {
			// TODO check if hieararchy is cgroup v2 only (unified mode)
			ms.Type = "cgroup2"
			ms.Source = "cgroup2"
			// cgroup filesystem is automounted even with lxc.rootfs.managed = 0
			// from 'man lxc.container.conf':
			// If cgroup namespaces are enabled, then any cgroup auto-mounting request will be ignored,
			// since the container can mount the filesystems itself, and automounting can confuse the container.
		}

		// TODO replace with symlink.FollowSymlinkInScope(filepath.Join(rootfs, "/etc/passwd"), rootfs) ?
		// "github.com/docker/docker/pkg/symlink"
		mountDest, err := resolveMountDestination(spec.Root.Path, ms.Destination)
		// Intermediate path resolution failed. This is not an error, since
		// the remaining directories / files are automatically created (create=dir|file)
		log.Trace().Err(err).Str("dst:", ms.Destination).Str("effective:", mountDest).Msg("resolve mount destination")

		// Check whether the resolved destination of the target link escapes the rootfs.
		if !filepath.HasPrefix(mountDest, spec.Root.Path) {
			// refuses mount destinations that escape from rootfs
			return fmt.Errorf("security violation: resolved mount destination path %s escapes from container root %s", mountDest, spec.Root.Path)
		}
		ms.Destination = mountDest

		err = createMountDestination(spec, &ms)
		if err != nil {
			return errors.Wrapf(err, "failed to create mount destination %s", ms.Destination)
		}

		mnt := fmt.Sprintf("%s %s %s %s", ms.Source, ms.Destination, ms.Type, strings.Join(ms.Options, ","))

		if err := clxc.SetConfigItem("lxc.mount.entry", mnt); err != nil {
			return err
		}
	}

	rootmnt := spec.Root.Path
	if item := c.ConfigItem("lxc.rootfs.mount"); len(item) > 0 {
		rootmnt = item[0]
	}

	// lxc handles read-only remount automatically, so no need for an additional remount entry
	for _, p := range spec.Linux.ReadonlyPaths {
		src := filepath.Join(rootmnt, p)
		mnt := fmt.Sprintf("%s %s %s %s", src, strings.TrimLeft(p, "/"), "none", "bind,ro,optional")
		if err := clxc.SetConfigItem("lxc.mount.entry", mnt); err != nil {
			return errors.Wrap(err, "failed to make path readonly")
		}
	}

	// pass context information as environment variables to hook scripts
	if err := clxc.SetConfigItem("lxc.hook.version", "1"); err != nil {
		return err
	}

	// If a Hostname is defined a new UTS namespace must be created.
	if spec.Hostname != "" {
		if !isNamespaceEnabled(spec, specs.UTSNamespace) {
			spec.Linux.Namespaces = append(spec.Linux.Namespaces, specs.LinuxNamespace{Type: specs.UTSNamespace})
		}

		if err := clxc.SetConfigItem("lxc.uts.name", spec.Hostname); err != nil {
			return err
		}
	}

	if err := configureNamespaces(c, spec); err != nil {
		return errors.Wrap(err, "failed to configure namespaces")
	}

	if err := configureContainerSecurity(ctx, c, spec); err != nil {
		return errors.Wrap(err, "failed to configure container security")
	}

	for key, val := range spec.Linux.Sysctl {
		if err := clxc.SetConfigItem("lxc.sysctl."+key, val); err != nil {
			return err
		}
	}
	return nil
}

// createMountDestination creates non-existent mount destination paths.
// This is required if rootfs is mounted readonly.
// When the source is a file that should be bind mounted a destination file is created.
// In any other case a target directory is created.
// We add 'create=dir' or 'create=file' to mount options because the mount destination
// may be shadowed by a previous mount. In this case lxc will create the mount destination.
// TODO check whether this is  desired behaviour in lxc ?
// Shouldn't the rootfs should be mounted readonly after all mounts destination directories have been created ?
// https://github.com/lxc/lxc/issues/1702
func createMountDestination(spec *specs.Spec, ms *specs.Mount) error {
	info, err := os.Stat(ms.Source)
	if err != nil && ms.Type == "bind" {
		// check if mountpoint is optional ?
		return errors.Wrapf(err, "failed to access source %s for bind mount", ms.Source)
	}

	if err == nil && !info.IsDir() {
		ms.Options = append(ms.Options, "create=file")
		// source exists and is not a directory
		// create a target file that can be used as target for a bind mount
		err := os.MkdirAll(filepath.Dir(ms.Destination), 0755)
		log.Debug().Err(err).Str("dst:", ms.Destination).Msg("create parent directory for file bind mount")
		if err != nil {
			return errors.Wrap(err, "failed to create mount destination dir")
		}
		f, err := os.OpenFile(ms.Destination, os.O_CREATE, 0440)
		log.Debug().Err(err).Str("dst:", ms.Destination).Msg("create file bind mount destination")
		if err != nil {
			return errors.Wrap(err, "failed to create file mountpoint")
		}
		return f.Close()
	}
	ms.Options = append(ms.Options, "create=dir")
	// FIXME exclude all directories that are below other mounts
	// only directories / files on the readonly rootfs must be created
	err = os.MkdirAll(ms.Destination, 0755)
	log.Debug().Err(err).Str("dst:", ms.Destination).Msg("create mount destination directory")
	if err != nil {
		return errors.Wrap(err, "failed to create mount destination")
	}
	return nil
}

func saveConfig(ctx *cli.Context, c *lxc.Container, configFilePath string) error {
	// Write out final config file for debugging and use with lxc-attach:
	// Do not edit config after this.
	err := c.SaveConfigFile(configFilePath)
	log.Debug().Err(err).Str("config", configFilePath).Msg("save config file")
	if err != nil {
		return errors.Wrapf(err, "failed to save config file to '%s'", configFilePath)
	}
	return nil

}

func makeSyncFifo(fifoFilename string) error {
	prevMask := unix.Umask(0000)
	defer unix.Umask(prevMask)
	if err := unix.Mkfifo(fifoFilename, 0666); err != nil {
		return errors.Wrapf(err, "failed to make fifo '%s'", fifoFilename)
	}
	return nil
}

func startConsole(cmd *exec.Cmd, consoleSocket string) error {
	addr, err := net.ResolveUnixAddr("unix", consoleSocket)
	if err != nil {
		return errors.Wrap(err, "failed to resolve console socket")
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return errors.Wrap(err, "connecting to console socket failed")
	}
	defer conn.Close()
	deadline := time.Now().Add(time.Second * 10)
	err = conn.SetDeadline(deadline)
	if err != nil {
		return errors.Wrap(err, "failed to set connection deadline")
	}

	sockFile, err := conn.File()
	if err != nil {
		return errors.Wrap(err, "failed to get file from unix connection")
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return errors.Wrap(err, "failed to start with pty")
	}
	defer ptmx.Close()

	// Send the pty file descriptor over the console socket (to the 'conmon' process)
	// For technical backgrounds see:
	// man sendmsg 2', 'man unix 3', 'man cmsg 1'
	// see https://blog.cloudflare.com/know-your-scm_rights/
	oob := unix.UnixRights(int(ptmx.Fd()))
	// Don't know whether 'terminal' is the right data to send, but conmon doesn't care anyway.
	err = unix.Sendmsg(int(sockFile.Fd()), []byte("terminal"), oob, nil, 0)
	if err != nil {
		return errors.Wrap(err, "failed to send console fd")
	}
	return nil
}

func startContainer(ctx *cli.Context, c *lxc.Container, spec *specs.Spec, timeout time.Duration) error {
	configFilePath := clxc.RuntimePath("config")
	cmd := exec.Command(clxc.StartCommand, c.Name(), clxc.RuntimeRoot, configFilePath)
	// Start container with a clean environment.
	// LXC will export variables defined in the config lxc.environment.
	// The environment variables defined by the container spec are exported within the init cmd CRIO_LXC_INIT_CMD.
	// This is required because environment variables defined by containers contain newlines and other tokens
	// that can not be handled properly by lxc.
	cmd.Env = []string{}

	if consoleSocket := ctx.String("console-socket"); consoleSocket != "" {
		if err := saveConfig(ctx, c, configFilePath); err != nil {
			return err
		}
		return startConsole(cmd, consoleSocket)
	}
	if !spec.Process.Terminal {
		// Inherit stdio from calling process (conmon).
		// lxc.console.path must be set to 'none' or stdio of init process is replaced with a PTY by lxc
		if err := clxc.SetConfigItem("lxc.console.path", "none"); err != nil {
			return errors.Wrap(err, "failed to disable PTY")
		}
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := saveConfig(ctx, c, configFilePath); err != nil {
		return err
	}

	if err := api.WriteSpec(spec, clxc.RuntimePath(api.INIT_SPEC)); err != nil {
		return errors.Wrapf(err, "failed to write init spec")
	}

	err := cmd.Start()
	if err != nil {
		return err
	}

	pidfile := ctx.String("pid-file")
	if pidfile != "" {
		log.Debug().Str("path:", pidfile).Msg("creating PID file")
		err := createPidFile(pidfile, cmd.Process.Pid)
		if err != nil {
			return err
		}
	}

	log.Debug().Msg("waiting for container creation")
	if !waitContainerCreated(c, timeout) {
		return fmt.Errorf("waiting for container timed out (%s)", timeout)
	}
	return nil
}

func waitContainerCreated(c *lxc.Container, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		log.Debug().Msg("container init state")
		pid, state := getContainerInitState(c)
		if pid > 0 && state == stateCreated {
			return true
		}
		time.Sleep(time.Millisecond * 50)
	}
	return false
}
