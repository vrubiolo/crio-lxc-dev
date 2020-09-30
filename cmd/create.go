package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"time"

	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/creack/pty"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	lxc "gopkg.in/lxc/go-lxc.v2"
)

var createCmd = cli.Command{
	Name:      "create",
	Usage:     "create a container from a bundle directory",
	ArgsUsage: "<containerID>",
	Action:    doCreate,
	Flags: []cli.Flag{
		&cli.StringFlag{
			// Is the bundle directory the runtime-root ?
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

// maps from CRIO namespace names to LXC names
var NamespaceMap = map[string]string{
	"cgroup":  "cgroup",
	"ipc":     "ipc",
	"mount":   "mnt",
	"network": "net",
	"pid":     "pid",
	"user":    "user",
	"uts":     "uts",
}

// TODO move busybox shell to lxcDir(CFG_DIR) and change interpreter in shell scripts
// to avoid conflicts with files from container image ....
func ensureShell(ctx *cli.Context, rootfs string) error {
	shPath := filepath.Join(rootfs, "bin/sh")
	if exists, _ := pathExists(shPath); exists {
		return nil
	}
	err := RunCommand("mkdir", "-p", filepath.Join(rootfs, "bin"))
	if err != nil {
		return errors.Wrapf(err, "Failed doing mkdir")
	}

	busyboxSrc := ctx.String("busybox-static")
	busyboxDst := filepath.Join(rootfs, "bin/busybox")
	busyboxLinks := []string{"bin/sh"}

	err = RunCommand("cp", busyboxSrc, busyboxDst)
	if err != nil {
		return errors.Wrapf(err, "Failed copying busybox %s", busyboxSrc)
	}
	for _, cmd := range busyboxLinks {
		err = RunCommand("ln", busyboxDst, filepath.Join(rootfs, cmd))
		if err != nil {
			return errors.Wrapf(err, "Failed linking %s", cmd)
		}
	}
	return nil
}

const (
	// CFG_DIR is bind mounted (readonly) to container
	CFG_DIR           = "/.crio-lxc"
	SYNC_FIFO         = "/syncfifo"
	SYNC_FIFO_PATH    = CFG_DIR + SYNC_FIFO
	SYNC_FIFO_CONTENT = "meshuggah rocks"
	INIT_CMD          = CFG_DIR + "/init.sh"
)

func getUserHome(spec *specs.Spec) string {
	passwd := filepath.Join(spec.Root.Path, "/etc/passwd")

	if _, err := os.Stat(passwd); err != nil {
		// search for passwd in mounts
		for _, m := range spec.Mounts {
			if m.Destination == passwd {
				passwd = m.Source
				break
			}
		}
	}
	if u := GetUser(passwd, spec.Process.User.Username); u != nil && u.Home != "" {
		return u.Home
	}
	return spec.Process.Cwd
}

func shellEscape(buf *strings.Builder, s string) {
	shellSpecials := []rune{'`', '"', '$', '\\'}
	buf.WriteRune('"')

	for i, r := range s {
		for _, rs := range shellSpecials {
			// escape unescaped quotes
			if r == rs && (i == 0 || s[i-1] != '\\') {
				buf.WriteRune('\\')
				break
			}
		}
		buf.WriteRune(r)
	}
	buf.WriteRune('"')
}

// Write the container init command to a file.
// The command file is then set as "lxc.execute.cmd"
// Every command argument is quoted and shell specials are escaped
// for `exec` to process them properly.
func setInitCmd(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	if err := clxc.SetConfigItem("lxc.environment", envStateCreated); err != nil {
		return err
	}

	buf := strings.Builder{}
	buf.WriteString("#!/bin/sh\n")
	// wait for start command
	fmt.Fprintf(&buf, "echo %q > %s\n", SYNC_FIFO_CONTENT, SYNC_FIFO_PATH)

	// export environment variables
	for _, envVar := range spec.Process.Env {
		keyVal := strings.SplitN(envVar, "=", 2)
		if len(keyVal) != 2 {
			return fmt.Errorf("Invalid environment variable %q", envVar)
		}
		fmt.Fprintf(&buf, "export %s=", keyVal[0])
		shellEscape(&buf, keyVal[1])
		buf.WriteRune('\n')
	}

	// after exec /proc/{pid}/environ reflects the new state
	fmt.Fprintf(&buf, "export %s\n", envStateRunning)
	fmt.Fprintf(&buf, "export HOME=%s\n", getUserHome(spec))

	// change to working directory before running exec
	fmt.Fprintf(&buf, "cd \"%s\"\n", spec.Process.Cwd)

	if len(spec.Process.Args) > 0 {
		buf.WriteString("exec")
		for _, arg := range spec.Process.Args {
			buf.WriteRune(' ')
			shellEscape(&buf, arg)
		}
		buf.WriteRune('\n')
	}

	cmdFile := clxc.RuntimePath(INIT_CMD)
	log.Debug().Str("filepath:", cmdFile).Msg("writing init file")
	err := ioutil.WriteFile(cmdFile, []byte(buf.String()), 0500)
	if err != nil {
		return err
	}
	// check that the int script can be executed
	err = unix.Access(cmdFile, unix.X_OK)
	if err != nil {
		return errors.Wrapf(err, "missing 'exec' permissions for %s (filesystem mounted with 'noexec' ?)", cmdFile)
	}
	// change permissions
	err = unix.Chown(cmdFile, int(spec.Process.User.UID), int(spec.Process.User.GID))
	if err != nil {
		return errors.Wrapf(err, "failed to set owner/group from spec.Process.User to %s", cmdFile)
	}
	return clxc.SetConfigItem("lxc.init.cmd", INIT_CMD)
}

// TODO ensure network and user namespace are shared together (why ?
func configureNamespaces(c *lxc.Container, spec *specs.Spec) error {
	procPidPathRE := regexp.MustCompile(`/proc/(\d+)/ns`)

	var nsToClone []string
	var configVal string
	seenNamespaceTypes := map[specs.LinuxNamespaceType]bool{}
	for _, ns := range spec.Linux.Namespaces {
		if _, ok := seenNamespaceTypes[ns.Type]; ok {
			return fmt.Errorf("duplicate namespace type %s", ns.Type)
		}
		seenNamespaceTypes[ns.Type] = true
		if ns.Path == "" {
			nsToClone = append(nsToClone, NamespaceMap[string(ns.Type)])
		} else {
			configKey := fmt.Sprintf("lxc.namespace.share.%s", NamespaceMap[string(ns.Type)])

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
	}

	if len(nsToClone) > 0 {
		configVal = strings.Join(nsToClone, " ")
		if err := clxc.SetConfigItem("lxc.namespace.clone", configVal); err != nil {
			return err
		}
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
	if err := checkRuntime(ctx); err != nil {
		return errors.Wrap(err, "runtime requirements check failed")
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
	spec, err := readBundleSpec(clxc.SpecPath)
	if err != nil {
		return errors.Wrap(err, "couldn't load bundle spec")
	}

	if err := configureContainer(ctx, c, spec); err != nil {
		return errors.Wrap(err, "failed to configure container")
	}

	return startContainer(ctx, c, spec, ctx.Duration("timeout"))
}

func configureContainerSecurity(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	// Crio sets the apparmor profile from the container spec.
	// The value *apparmor_profile*  from crio.conf is used if no profile is defined by the container.
	aaprofile := spec.Process.ApparmorProfile
	if aaprofile == "" {
		aaprofile = "unconfined"
	}
	if err := clxc.SetConfigItem("lxc.apparmor.profile", aaprofile); err != nil {
		return err
	}

	if spec.Process.OOMScoreAdj != nil {
		if err := clxc.SetConfigItem("lxc.proc.oom_score_adj", fmt.Sprintf("%d", *spec.Process.OOMScoreAdj)); err != nil {
			return err
		}
	}

	if spec.Process.NoNewPrivileges {
		if err := clxc.SetConfigItem("lxc.no_new_privs", "1"); err != nil {
			return err
		}
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
// NOTE Capabilities support must be enabled explicitly when compiling liblxc. ( --enable-capabilities)
// The container will not start if spec.Process.Capabilities is defined and liblxc has no capablities support.
// See `man lxc.container.conf` lxc.cap.drop and lxc.cap.keep for details.
// https://blog.container-solutions.com/linux-capabilities-in-practice
// https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work
func configureCapabilities(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	keepCaps := "none"
	if spec.Process.Capabilities != nil {
		var caps []string
		for _, c := range spec.Process.Capabilities.Permitted {
			lcCapName := strings.TrimPrefix(strings.ToLower(c), "cap_")
			caps = append(caps, lcCapName)
		}
		keepCaps = strings.Join(caps, " ")
	}

	if err := clxc.SetConfigItem("lxc.cap.keep", keepCaps); err != nil {
		return err
	}
	return nil
}

func isDeviceEnabled(spec *specs.Spec, dev specs.LinuxDevice) bool {
	for _, specDev := range spec.Linux.Devices {
		if specDev.Path == dev.Path {
			return true
		}
	}
	return false
}

func addDevice(spec *specs.Spec, dev specs.LinuxDevice, mode os.FileMode, uid, gid uint32) {
	dev.FileMode = &mode
	dev.UID = &uid
	dev.GID = &gid
	spec.Linux.Devices = append(spec.Linux.Devices, dev)

	devCgroup := specs.LinuxDeviceCgroup{Allow: true, Type: dev.Type, Major: &dev.Major, Minor: &dev.Minor, Access: "rwm"}
	spec.Linux.Resources.Devices = append(spec.Linux.Resources.Devices, devCgroup)
}

// ensureDefaultDevices adds the mandatory devices defined in https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md#default-devices
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
		specs.LinuxDevice{Path: "/dev/ptmx", Type: "c", Major: 5, Minor: 2},
	}

	// add missing default devices
	for _, dev := range devices {
		if !isDeviceEnabled(spec, dev) {
			addDevice(spec, dev, mode, uid, gid)
		}
	}
	return nil
}

// https://github.com/opencontainers/runtime-spec/blob/v1.0.2/config-linux.md
// TODO New spec will contain a property Unified for cgroupv2 properties
// https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md#unified
func configureCgroupResources(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	linux := spec.Linux

	// lxc.cgroup.root and lxc.cgroup.relative must not be set for cgroup v2

	if linux.CgroupsPath != "" {
		if err := clxc.SetConfigItem("lxc.cgroup.dir", linux.CgroupsPath); err != nil {
			return err
		}
	}

	if err := addHookCreateDevices(ctx, c, spec); err != nil {
		return errors.Wrapf(err, "failed to add create devices hook")
	}

	// Set cgroup device permissions.
	// Device rule parsing in LXC is not well documented in lxc.container.conf
	// see https://github.com/lxc/lxc/blob/79c66a2af36ee8e967c5260428f8cdb5c82efa94/src/lxc/cgroups/cgfsng.c#L2545
	// mixing allow/deny is not permitted by lxc.cgroup2.devices
	// either build up a deny list or an allow list
	devicesAllow := "lxc.cgroup2.devices.allow"
	devicesDeny := "lxc.cgroup2.devices.deny"

	anyDevice := ""
	blockDevice := "b"
	charDevice := "c"

	for _, dev := range linux.Resources.Devices {
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

	// Memory restriction configuration
	if mem := linux.Resources.Memory; mem != nil {
		log.Debug().Msg("TODO configure cgroup memory controller")
	}
	// CPU resource restriction configuration
	if cpu := linux.Resources.CPU; cpu != nil {
		// use strconv.FormatUint(n, 10) instead of fmt.Sprintf ?
		log.Debug().Msg("configure cgroup cpu controller")
		if cpu.Shares != nil && *cpu.Shares > 0 {
			/*
				if err := clxc.SetConfigItem("lxc.cgroup2.cpu.shares", fmt.Sprintf("%d", *cpu.Shares)); err != nil {
					return err
				}
			*/
		}
		if cpu.Quota != nil && *cpu.Quota > 0 {
			if err := clxc.SetConfigItem("lxc.cgroup2.cpu.cfs_quota_us", fmt.Sprintf("%d", *cpu.Quota)); err != nil {
				return err
			}
		}
		/*
			if cpu.Period != nil && *cpu.Period != 0 {
				if err := clxc.SetConfigItem("lxc.cgroup2.cpu.cfs_period_us", fmt.Sprintf("%d", *cpu.Period)); err != nil {
					return err
				}
			}
		*/
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

// The hook is run within the host namespace, after all rootfs setup is completed.
func addHookCreateDevices(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	hookPath := clxc.RuntimePath("create_devices.sh")
	log.Debug().Str("path:", hookPath).Msg("create device hook")
	f, err := os.OpenFile(hookPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0750)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := ensureDefaultDevices(spec); err != nil {
		return err
	}

	if clxc.LogLevel == lxc.TRACE {
		fmt.Fprintln(f, "#!/bin/sh -x")
	} else {
		fmt.Fprintln(f, "#!/bin/sh")
	}
	fmt.Fprintf(f, "cd $LXC_ROOTFS_MOUNT\n")
	for _, dev := range spec.Linux.Devices {
		mode := os.FileMode(0666)
		if dev.FileMode != nil {
			mode = *dev.FileMode
		}
		uid := spec.Process.User.UID
		if dev.UID != nil {
			uid = *dev.UID
		}
		gid := spec.Process.User.GID
		if dev.GID != nil {
			gid = *dev.GID
		}
		fmt.Fprintf(f, "mkdir -p .%s\n", filepath.Dir(dev.Path))
		fmt.Fprintf(f, "mknod -m %s .%s %s %d %d || exit 1\n", accessMask(mode), dev.Path, dev.Type, dev.Major, dev.Minor)
		fmt.Fprintf(f, "chown -v %d:%d .%s || exit 1\n", uid, gid, dev.Path)
	}
	return clxc.SetConfigItem("lxc.hook.mount", hookPath)
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

	err := RunCommand("mkdir", "-p", "-m", "0750", filepath.Join(spec.Root.Path, CFG_DIR))
	if err != nil {
		return errors.Wrapf(err, "Failed creating %s in rootfs", CFG_DIR)
	}
	err = RunCommand("mkdir", "-p", "-m", "0750", clxc.RuntimePath(CFG_DIR))
	if err != nil {
		return errors.Wrapf(err, "Failed creating %s in lxc container dir", CFG_DIR)
	}

	mounts := spec.Mounts

	mounts = append(mounts, specs.Mount{
		Source:      clxc.RuntimePath(CFG_DIR),
		Destination: strings.Trim(CFG_DIR, "/"),
		Type:        "bind",
		Options:     []string{"bind", "ro"},
	})

	// create named fifo in lxcpath and mount it into the container
	if err := makeSyncFifo(clxc.RuntimePath(SYNC_FIFO_PATH)); err != nil {
		return errors.Wrapf(err, "failed to make sync fifo")
	}

	rootfsOptions := ""
	if spec.Root.Readonly {
		rootfsOptions = "ro"
		// Bug in lxc ? (rootfs should be mounted readonly after all mounts destination directories have been created ?)
		// https://github.com/lxc/lxc/issues/1702
	}
	if err := clxc.SetConfigItem("lxc.rootfs.options", rootfsOptions); err != nil {
		return err
	}
	// excplicitly disable auto-mounting
	if err := clxc.SetConfigItem("lxc.mount.auto", ""); err != nil {
		return err
	}

	for _, ms := range mounts {
		if ms.Type == "cgroup" {
		  ms.Type = "cgroup2"
		  ms.Source = "cgroup2"
			// cgroup filesystem is automounted even with lxc.rootfs.managed = 0
			// from 'man lxc.container.conf':
			// If cgroup namespaces are enabled, then any cgroup auto-mounting request will be ignored,
			// since the container can mount the filesystems itself, and automounting can confuse the container.
			// Make cgroup mountpoint optional if cgroup namespace is not enabled (shared or cloned)

			// namespace check does not work for calico pod/calico-kube-controllers-c9784d67d-2xpgx
			// cgroupfs is already mounted (because it is shared with the host ?)
			//if isNamespaceEnabled(spec, specs.CgroupNamespace) {

			// TODO check cgroupfs is mounted correctly in calico-kube-controllers
			//	ms.Options = append(ms.Options, "optional")
			//}
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

	// LXC does not yet implement masking paths see https://github.com/lxc/lxc/issues/2282
	for _, p := range spec.Linux.MaskedPaths {
		// see https://github.com/opencontainers/runc/blob/64416d34f30eaf69af6938621137b393ada63a16/libcontainer/container_linux.go#L855
		// Existing files are masked with the hosts null device /dev/null
		// If the path to mask is a directory we make it readonly instead, since
		// The `optional` mount option is set to let lxc skip over invalid / inaccessible paths.

		// TODO masking paths only works if destination is a file
		// Can apparmor be used to mask paths instead ?
		mnt := fmt.Sprintf("%s %s %s %s", "/dev/null", strings.TrimLeft(p, "/"), "none", "bind,optional")
		if err := clxc.SetConfigItem("lxc.mount.entry", mnt); err != nil {
			return errors.Wrap(err, "failed to mask path")
		}
	}
	// lxc handles read-only remount automatically, so no need for an additional remount entry
	for _, p := range spec.Linux.ReadonlyPaths {
		src := filepath.Join(rootmnt, p)
		mnt := fmt.Sprintf("%s %s %s %s", src, strings.TrimLeft(p, "/"), "none", "bind,ro,optional")
		if err := clxc.SetConfigItem("lxc.mount.entry", mnt); err != nil {
			return errors.Wrap(err, "failed to make path readonly")
		}
	}

	if err := ensureShell(ctx, spec.Root.Path); err != nil {
		return errors.Wrap(err, "couldn't ensure a shell exists in container")
	}

	if err := setInitCmd(ctx, c, spec); err != nil {
		return errors.Wrap(err, "failed to set lxc.init.cmd")
	}

	if err := clxc.SetConfigItem("lxc.uts.name", spec.Hostname); err != nil {
		return err
	}

	// pass context information as environment variables to hook scripts
	if err := clxc.SetConfigItem("lxc.hook.version", "1"); err != nil {
		return err
	}

	if err := configureNamespaces(c, spec); err != nil {
		return errors.Wrap(err, "failed to configure namespaces")
	}

	if err := configureContainerSecurity(ctx, c, spec); err != nil {
		return errors.Wrap(err, "failed to configure container security")
	}
	return nil
}

// createMountDestination creates non-existent mount destination paths.
// This is required if rootfs is mounted readonly.
// When the source is a file that should be bind mounted a destination file is created.
// In any other case a target directory is created.
// We add 'create=dir' or 'create=file' to mount options because the mount destination
// may be shadowed by a previous mount. In this case lxc will create the mount destination.
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
	// clear environment
	// if environment is non-empty e.g /etc/crio/crio.conf specifies conmon_env (other than PATH)
	// then lxc does not export lxc.environment variables ....
	// so we can set the process environment here if we want
	cmd.Env = []string{}

	if consoleSocket := ctx.String("console-socket"); consoleSocket != "" {
		if err := saveConfig(ctx, c, configFilePath); err != nil {
			return err
		}
		return startConsole(cmd, consoleSocket)
	}
	if !spec.Process.Terminal {
		// Inherit stdio from calling process (conmon)
		// lxc.console.path must be set to 'none' or stdio of init process is replaced with a PTY
		// see https://github.com/lxc/lxc/blob/531e0128036542fb959b05eceec78e52deefafe0/src/lxc/start.c#L1252
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
	err := cmd.Start()
	if err != nil {
		return err
	}
	//cmd.Process.Release()

	log.Debug().Msg("waiting for PID file")
	pidfile := ctx.String("pid-file")
	if pidfile != "" {
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
