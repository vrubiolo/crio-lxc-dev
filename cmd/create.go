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

	"github.com/apex/log"
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
			Name:  "bundle",
			Usage: "set bundle directory",
			Value: ".",
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
			Name:  "timeout",
			Usage: "timeout for container creation",
			Value: time.Second * 5,
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

// Write the container init command to a file.
// The command file is then set as "lxc.execute.cmd"
// Every command argument is quoted and shell specials are escaped
// for `exec` to process them properly.
func setInitCmd(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {

	if err := c.SetConfigItem("lxc.environment", envStateCreated); err != nil {
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
		fmt.Fprintf(&buf, "export %s=\"%s\"\n", keyVal[0], keyVal[1])
	}

	// after exec /proc/{pid}/environ reflects the new state
	fmt.Fprintf(&buf, "export %s\n", envStateRunning)
	fmt.Fprintf(&buf, "export HOME=%s\n", getUserHome(spec))

	// change to working directory before running exec
	fmt.Fprintf(&buf, "cd \"%s\"\n", spec.Process.Cwd)

	if len(spec.Process.Args) > 0 {
		buf.WriteString("exec")
		escape := []rune{'`', '"', '$', '\\'}

		for _, arg := range spec.Process.Args {
			buf.WriteRune(' ')
			buf.WriteRune('"')

			for i, r := range arg {
				for _, er := range escape {
					// escape unescaped quotes
					if r == er && (i == 0 || arg[i-1] != '\\') {
						buf.WriteRune('\\')
						continue
					}
				}
				buf.WriteRune(r)
			}
			buf.WriteRune('"')
		}
		buf.WriteRune('\n')
	}

	cmdFile := clxc.RuntimePath(INIT_CMD)
	log.Debugf("Writing lxc.init.cmd file to %s", cmdFile)
	err := ioutil.WriteFile(cmdFile, []byte(buf.String()), 0500)
	if err != nil {
		return err
	}
	// check that the int script can be executed
	err = unix.Access(cmdFile, unix.X_OK)
	if err != nil {
		return errors.Wrapf(err, "missing 'exec' permissions for %s (filesystem mounted with 'noexec' ?)", cmdFile)
	}
	return c.SetConfigItem("lxc.init.cmd", INIT_CMD)
}

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

			if err := c.SetConfigItem(configKey, configVal); err != nil {
				return errors.Wrapf(err, "failed to set namespace config: '%s'='%s'", configKey, configVal)
			}
		}
	}

	if len(nsToClone) > 0 {
		configVal = strings.Join(nsToClone, " ")
		if err := c.SetConfigItem("lxc.namespace.clone", configVal); err != nil {
			return errors.Wrapf(err, "failed to set lxc.namespace.clone=%s", configVal)
		}
	}
	return nil
}

func doCreate(ctx *cli.Context) error {
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

	if err := c.SetConfigItem("lxc.log.file", clxc.LogFilePath); err != nil {
		return errors.Wrapf(err, "failed to lxc.log.file: '%s'", clxc.LogFilePath)
	}

	err = c.SetLogLevel(clxc.LogLevel)
	if err != nil {
		return errors.Wrap(err, "failed to set container loglevel")
	}
	if clxc.LogLevel == lxc.TRACE {
		c.SetVerbosity(lxc.Verbose)
	}

	specPath := filepath.Join(ctx.String("bundle"), "config.json")
	/*
	  err =	RunCommand("cp", specPath, lxcPathDir("spec.json"))
	  if err != nil {
	    return errors.Wrap(err, "failed to copy bundle spec")
	  }
	*/
	spec, err := readBundleSpec(specPath)
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
	if err := c.SetConfigItem("lxc.apparmor.profile", aaprofile); err != nil {
		return errors.Wrapf(err, "failed to set apparmor.profile to %s", aaprofile)
	}

	if spec.Process.OOMScoreAdj != nil {
		if err := c.SetConfigItem("lxc.proc.oom_score_adj", fmt.Sprintf("%d", *spec.Process.OOMScoreAdj)); err != nil {
			return errors.Wrap(err, "failed to set lxc.proc.oom_score_adj")
		}
	}

	if spec.Process.NoNewPrivileges {
		if err := c.SetConfigItem("lxc.no_new_privs", "1"); err != nil {
			return errors.Wrapf(err, "failed to set lxc.no_new_privs")
		}
	}

	// Do not set "lxc.ephemeral=1" since resources not created by
	// the container runtime MUST NOT be deleted by the container runtime.
	if err := c.SetConfigItem("lxc.ephemeral", "0"); err != nil {
		return errors.Wrapf(err, "failed to set lxc.ephemeral=0")
	}

	if err := configureCapabilities(ctx, c, spec); err != nil {
		return errors.Wrapf(err, "failed to configure capabilities")
	}

	if err := c.SetConfigItem("lxc.init.uid", fmt.Sprintf("%d", spec.Process.User.UID)); err != nil {
		return errors.Wrapf(err, "failed to set lxc.init.uid")
	}
	if err := c.SetConfigItem("lxc.init.gid", fmt.Sprintf("%d", spec.Process.User.GID)); err != nil {
		return errors.Wrapf(err, "failed to set lxc.init.uid")
	}

	// See `man lxc.container.conf` lxc.idmap.
	for _, m := range spec.Linux.UIDMappings {
		if err := c.SetConfigItem("lxc.idmap", fmt.Sprintf("u %d %d %d", m.ContainerID, m.HostID, m.Size)); err != nil {
			return errors.Wrapf(err, "failed to set lxc.idmap")
		}
	}

	for _, m := range spec.Linux.GIDMappings {
		if err := c.SetConfigItem("lxc.idmap", fmt.Sprintf("g %d %d %d", m.ContainerID, m.HostID, m.Size)); err != nil {
			return errors.Wrapf(err, "failed to set lxc.idmap")
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

	log.Debugf("Keeping capabilities: %s", keepCaps)
	if err := c.SetConfigItem("lxc.cap.keep", keepCaps); err != nil {
		return errors.Wrapf(err, "failed to set lxc.cap.keep")
	}
	return nil
}

func ensureDevNull(spec *specs.Spec) {
	for _, dev := range spec.Linux.Devices {
		if dev.Path == "/dev/null" {
			return
		}
	}
	mode := os.ModePerm
	var uid, gid uint32 = 0, 0
	devNull := specs.LinuxDevice{Path: "/dev/null", Type: "c", Major: 1, Minor: 3, FileMode: &mode, UID: &uid, GID: &gid}
	spec.Linux.Devices = append(spec.Linux.Devices, devNull)
}

func configureCgroupResources(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	linux := spec.Linux

	if ctx.Bool("systemd-cgroup") {
		c.SetConfigItem("lxc.cgroup.root", "system.slice")
	}

	if linux.CgroupsPath != "" {
		c.SetConfigItem("lxc.cgroup.dir", linux.CgroupsPath)
	}

	c.SetConfigItem("lxc.cgroup.relative", "1")

	// autodev is required ?
	c.SetConfigItem("lxc.autodev", "0") // TODO  create /dev/null ?
	// if autodev is disable lxc spits out these warnings:
	// WARN utils - utils.c:fix_stdio_permissions:1874 - No such file or directory - Failed to open "/dev/null"
	// WARN start - start.c:do_start:1371 - Failed to ajust stdio permissions
	if len(spec.Linux.Devices) > 0 {
		if err := addHookCreateDevices(ctx, c, spec); err != nil {
			return errors.Wrapf(err, "failed to add create devices hook")
		}
	}

	// Set cgroup device permissions.
	// Device rule parsing in LXC is not well documented in lxc.container.conf
	// see https://github.com/lxc/lxc/blob/79c66a2af36ee8e967c5260428f8cdb5c82efa94/src/lxc/cgroups/cgfsng.c#L2545
	for _, dev := range linux.Resources.Devices {
		key := "lxc.cgroup.devices.deny"
		if dev.Allow {
			key = "lxc.cgroup.devices.allow"
		}

		devType := "a" // 'type' is a (all), c (char), or b (block).
		if dev.Type != "" {
			devType = dev.Type
		}

		maj := "*"
		if dev.Major != nil {
			maj = fmt.Sprintf("%d", *dev.Major)
		}

		min := "*"
		if dev.Minor != nil {
			min = fmt.Sprintf("%d", *dev.Minor)
		}
		val := fmt.Sprintf("%s %s:%s %s", devType, maj, min, dev.Access)
		if err := c.SetConfigItem(key, val); err != nil {
			return errors.Wrapf(err, "failed to set %s", key)
		}
	}

	// allow /dev/null
	if err := c.SetConfigItem("lxc.cgroup.devices.allow", "c 1:3 rw"); err != nil {
		return errors.Wrapf(err, "failed to allow access to /dev/null")
	}
	// /dev/zero
	if err := c.SetConfigItem("lxc.cgroup.devices.allow", "c 1:5 r"); err != nil {
		return errors.Wrapf(err, "failed to allow access to /dev/zero")
	}
	// /dev/urandom
	if err := c.SetConfigItem("lxc.cgroup.devices.allow", "c 1:9 rw"); err != nil {
		return errors.Wrapf(err, "failed to allow access to /dev/urandom")
	}

	// Memory restriction configuration
	if mem := linux.Resources.Memory; mem != nil {
		log.Debugf("TODO configure cgroup memory controller")
	}
	// CPU resource restriction configuration
	if cpu := linux.Resources.CPU; cpu != nil {
		// use strconv.FormatUint(n, 10) instead of fmt.Sprintf ?
		log.Debugf("configure cgroup cpu controller")
		if cpu.Shares != nil && *cpu.Shares > 0 {
			if err := c.SetConfigItem("lxc.cgroup.cpu.shares", fmt.Sprintf("%d", *cpu.Shares)); err != nil {
				return errors.Wrap(err, "failed to set lxc.cgroup.cpu.shares")
			}
		}
		if cpu.Quota != nil && *cpu.Quota > 0 {
			if err := c.SetConfigItem("lxc.cgroup.cpu.cfs_quota_us", fmt.Sprintf("%d", *cpu.Quota)); err != nil {
				return errors.Wrap(err, "failed to set lxc.cgroup.cpu.cfs_quota_us")
			}
		}
		if cpu.Period != nil && *cpu.Period != 0 {
			if err := c.SetConfigItem("lxc.cgroup.cpu.cfs_period_us", fmt.Sprintf("%d", *cpu.Period)); err != nil {
				return errors.Wrap(err, "failed to set lxc.cgroup.cpu.cfs_period_us")
			}
		}
		if cpu.Cpus != "" {
			if err := c.SetConfigItem("lxc.cgroup.cpuset.cpus", cpu.Cpus); err != nil {
				return errors.Wrap(err, "failed to set lxc.cgroup.cpuset.cpus")
			}
		}
		if cpu.RealtimePeriod != nil && *cpu.RealtimePeriod > 0 {
			if err := c.SetConfigItem("lxc.cgroup.cpu.rt_period_us", fmt.Sprintf("%d", *cpu.RealtimePeriod)); err != nil {
				return errors.Wrap(err, "failed to set lxc.cgroup.cpu.rt_period_us")
			}
		}
		if cpu.RealtimeRuntime != nil && *cpu.RealtimeRuntime > 0 {
			if err := c.SetConfigItem("lxc.cgroup.cpu.rt_runtime_us", fmt.Sprintf("%d", *cpu.RealtimeRuntime)); err != nil {
				return errors.Wrap(err, "failed to set lxc.cgroup.cpu.rt_runtime_us")
			}
		}
		// Mems string `json:"mems,omitempty"`
	}

	// Task resource restriction configuration.
	if pids := linux.Resources.Pids; pids != nil {
		if err := c.SetConfigItem("lxc.cgroup.pids.max", fmt.Sprintf("%d", pids.Limit)); err != nil {
			return errors.Wrap(err, "failed to set lxc.cgroup.pids.max")
		}
	}
	// BlockIO restriction configuration
	if blockio := linux.Resources.BlockIO; blockio != nil {
		log.Debugf("TODO configure cgroup blockio controller")
	}
	// Hugetlb limit (in bytes)
	if hugetlb := linux.Resources.HugepageLimits; hugetlb != nil {
		log.Debugf("TODO configure cgroup hugetlb controller")
	}
	// Network restriction configuration
	if net := linux.Resources.Network; net != nil {
		log.Debugf("TODO configure cgroup network controllers")
	}
	return nil
}

// The hook is run within the host namespace, after all rootfs setup is completed.
func addHookCreateDevices(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	hookPath := clxc.RuntimePath("create_devices.sh")
	f, err := os.OpenFile(hookPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0750)
	if err != nil {
		return err
	}
	defer f.Close()

	//ensureDevNull(spec)

	fmt.Fprintln(f, "#!/bin/sh -x")
	fmt.Fprintf(f, "cd $LXC_ROOTFS_MOUNT\n")
	for _, dev := range spec.Linux.Devices {
		mode := os.FileMode(0777) // umask ?
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
		//fmt.Fprintf(f, "if ! [ -e \".%s\" ]; then\n", dev.Path)
		fmt.Fprintf(f, "mkdir -p .%s\n", filepath.Dir(dev.Path))
		fmt.Fprintf(f, "mknod -m %s .%s %s %d %d || exit 1\n", accessMask(mode), dev.Path, dev.Type, dev.Major, dev.Minor)
		fmt.Fprintf(f, "chown -v %d:%d .%s || exit 1\n", uid, gid, dev.Path)
		//fmt.Fprintf(f, "fi\n")
	}
	//fmt.Fprintf(f, "sleep 1\n")
	return c.SetConfigItem("lxc.hook.mount", hookPath)
}

func accessMask(stat os.FileMode) string {
	/*
	  A numeric mode is from one to four octal digits (0-7), derived by adding up the bits with values 4, 2, and 1. Omitted digits are assumed to be leading zeros. The first digit selects the set user ID (4) and set group ID (2) and restricted deletion or sticky (1) attributes. The second digit selects permissions for the user who owns the file: read (4), write (2), and execute (1); the third selects permissions for other users in the file's group, with the same values; and the fourth for other users not in the file's group, with the same values.
	*/

	pos1 := 0
	if stat&os.ModeSetuid == os.ModeSetuid {
		pos1 += 4
	}
	if stat&os.ModeSetgid == os.ModeSetgid {
		pos1 += 2
	}
	if stat&os.ModeSticky == os.ModeSticky {
		pos1 += 1
	}

	return fmt.Sprintf("0%d%03o", pos1, stat.Perm())
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

	if err := c.SetConfigItem("lxc.rootfs.path", spec.Root.Path); err != nil {
		return errors.Wrapf(err, "failed to set rootfs: '%s'", spec.Root.Path)
	}

	if err := c.SetConfigItem("lxc.rootfs.managed", "0"); err != nil {
		return errors.Wrap(err, "failed to set rootfs.managed to 0")
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
	if err := c.SetConfigItem("lxc.rootfs.options", rootfsOptions); err != nil {
		return errors.Wrap(err, "failed to set lxc.rootfs.options")
	}

	for _, ms := range mounts {
		if ms.Type == "cgroup" {
			// cgroup filesystem is automounted even with lxc.rootfs.managed = 0
			// from 'man lxc.container.conf':
			// If cgroup namespaces are enabled, then any cgroup auto-mounting request will be ignored,
			// since the container can mount the filesystems itself, and automounting can confuse the container.
			// Make cgroup mountpoint optional if cgroup namespace is not enabled (shared or cloned)
			if !isNamespaceEnabled(spec, specs.CgroupNamespace) {
				ms.Options = append(ms.Options, "optional")
			}
		}

		// TODO replace with symlink.FollowSymlinkInScope(filepath.Join(rootfs, "/etc/passwd"), rootfs) ?
		// "github.com/docker/docker/pkg/symlink"
		mountDest, err := resolveMountDestination(spec.Root.Path, ms.Destination)
		// Intermediate path resolution failed. This is not an error, since
		// the remaining directories / files are automatically created (create=dir|file)
		if err != nil {
			log.Debugf("resolveMountDestination: %s --> %s (err:%s)", ms.Destination, mountDest, err)
		} else {
			log.Debugf("resolveMountDestination: %s --> %s)", ms.Destination, mountDest)
		}

		// Check whether the resolved destination of the target link escapes the rootfs.
		if !filepath.HasPrefix(mountDest, spec.Root.Path) {
			// refuses mount destinations that escape from rootfs
			return fmt.Errorf("security violation: resolved mount destination path %s escapes from container root %s", mountDest, spec.Root.Path)
		}
		ms.Destination = mountDest

		_, err = os.Stat(ms.Destination)
		if os.IsNotExist(err) {
			createMountDestination(spec, &ms)
		} else {
			if err != nil {
				return errors.Wrapf(err, "mount destination %s unavailable", ms.Destination)
			}
		}

		opts := strings.Join(ms.Options, ",")
		mnt := fmt.Sprintf("%s %s %s %s", ms.Source, ms.Destination, ms.Type, opts)
		log.Debugf("adding mount entry %q", mnt)

		if err := c.SetConfigItem("lxc.mount.entry", mnt); err != nil {
			return errors.Wrap(err, "failed to set mount config")
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

		// will fail if target is a directory, maybe use apparmor instead ?
		mnt := fmt.Sprintf("%s %s %s %s", "/dev/null", strings.TrimLeft(p, "/"), "none", "bind,optional")
		if err := c.SetConfigItem("lxc.mount.entry", mnt); err != nil {
			return errors.Wrapf(err, "failed to mask path %s", p)
		}
	}
	// lxc handles read-only remount automatically, so no need for an additional remount entry
	for _, p := range spec.Linux.ReadonlyPaths {
		src := filepath.Join(rootmnt, p)
		mnt := fmt.Sprintf("%s %s %s %s", src, strings.TrimLeft(p, "/"), "none", "bind,ro,optional")
		if err := c.SetConfigItem("lxc.mount.entry", mnt); err != nil {
			return errors.Wrapf(err, "failed to mount %s readonly", p)
		}
	}

	if err := ensureShell(ctx, spec.Root.Path); err != nil {
		return errors.Wrap(err, "couldn't ensure a shell exists in container")
	}

	if err := setInitCmd(ctx, c, spec); err != nil {
		return errors.Wrap(err, "failed to set lxc.init.cmd")
	}

	if err := c.SetConfigItem("lxc.uts.name", spec.Hostname); err != nil {
		return errors.Wrap(err, "failed to set hostname")
	}

	if err := c.SetConfigItem("lxc.hook.version", "1"); err != nil {
		return errors.Wrap(err, "failed to set hook version")
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
	if ms.Type == "bind" {
		info, err := os.Stat(ms.Source)
		if err != nil {
			return errors.Wrapf(err, "source %s for bind mount does not exist", ms.Source)
		}
		if !info.IsDir() {
			log.Debugf("creating mount target file %s", ms.Destination)
			ms.Options = append(ms.Options, "create=file")
			// source exists and is not a directory
			// create a target file that can be used as target for a bind mount
			err := os.MkdirAll(filepath.Dir(ms.Destination), 0755)
			if err != nil {
				return errors.Wrap(err, "failed to create mount destination dir")
			}
			f, err := os.OpenFile(ms.Destination, os.O_CREATE, 0440)
			if err != nil {
				return errors.Wrap(err, "failed to create mount destination file")
			}
			return f.Close()
		}
	}

	ms.Options = append(ms.Options, "create=dir")
	log.Debugf("creating mount target destination %s", ms.Destination)
	if filepath.Base(ms.Destination) != filepath.Join(spec.Root.Path, "/dev") {
		err := os.MkdirAll(ms.Destination, 0755)
		if err != nil {
			return errors.Wrap(err, "failed to create mount destination")
		}
	}
	return nil
}

func saveConfig(ctx *cli.Context, c *lxc.Container, configFilePath string) error {
	log.Debugf("Saving config file %s", configFilePath)
	// Write out final config file for debugging and use with lxc-attach:
	// Do not edit config after this.
	if err := c.SaveConfigFile(configFilePath); err != nil {
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
	configFilePath := filepath.Join(LXC_PATH, c.Name(), "config")
	runtime := ctx.String("runtime")
	cmd := exec.Command(runtime, c.Name(), LXC_PATH, configFilePath)
	log.Debugf("Starting runtime: %s", cmd.Args)

	if consoleSocket := ctx.String("console-socket"); consoleSocket != "" {
		if err := saveConfig(ctx, c, configFilePath); err != nil {
			return err
		}
		err := startConsole(cmd, consoleSocket)
		if err != nil {
			return err
		}
	} else {
		if !spec.Process.Terminal {
			// Inherit stdio from calling process (conmon)
			// lxc.console.path must be set to 'none' or stdio of init process is replaced with a PTY
			// see https://github.com/lxc/lxc/blob/531e0128036542fb959b05eceec78e52deefafe0/src/lxc/start.c#L1252
			if err := c.SetConfigItem("lxc.console.path", "none"); err != nil {
				return errors.Wrapf(err, "failed to disable PTY")
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
	}
	pidfile := ctx.String("pid-file")
	if pidfile != "" {
		err := createPidFile(pidfile, cmd.Process.Pid)
		if err != nil {
			return err
		}
	}

	if !waitContainerCreated(c, timeout) {
		return fmt.Errorf("container creation timeout (%s) expired", timeout)
	}
	return nil
}

func waitContainerCreated(c *lxc.Container, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pid, state := getContainerInitState(c)
		if pid > 0 && state == stateCreated {
			return true
		}
		time.Sleep(time.Millisecond * 50)
	}
	return false
}
