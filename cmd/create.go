package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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

	if err := configureMounts(spec); err != nil {
	  return err
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
	return clxc.waitContainerCreated(timeout)
}

