package main

import (
	"fmt"
	"golang.org/x/sys/unix"

	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli"

	lxc "gopkg.in/lxc/go-lxc.v2"
)

var createCmd = cli.Command{
	Name:      "create",
	Usage:     "create a container from a bundle directory",
	ArgsUsage: "<containerID>",
	Action:    doCreate,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "bundle",
			Usage: "set bundle directory",
			Value: ".",
		},
		cli.IntFlag{
			Name:  "console-socket",
			Usage: "pty master FD", // TODO not handled yet
		},
		cli.StringFlag{
			Name:  "pid-file",
			Usage: "path to write container PID", // TODO not handled yet
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

func ensureShell(rootfs string) error {
	shPath := filepath.Join(rootfs, "bin/sh")
	if exists, _ := pathExists(shPath); exists {
		return nil
	}
	var err error
	err = RunCommand("mkdir", filepath.Join(rootfs, "bin"))
	if err != nil {
		return errors.Wrapf(err, "Failed doing mkdir")
	}
	err = RunCommand("cp", "/bin/busybox", filepath.Join(rootfs, "bin/"))
	if err != nil {
		return errors.Wrapf(err, "Failed copying busybox")
	}
	err = RunCommand("ln", filepath.Join(rootfs, "bin/busybox"), filepath.Join(rootfs, "bin/stat"))
	if err != nil {
		return errors.Wrapf(err, "Failed linking stat")
	}
	err = RunCommand("ln", filepath.Join(rootfs, "bin/busybox"), filepath.Join(rootfs, "bin/sh"))
	if err != nil {
		return errors.Wrapf(err, "Failed linking sh")
	}
	err = RunCommand("ln", filepath.Join(rootfs, "bin/busybox"), filepath.Join(rootfs, "bin/tee"))
	if err != nil {
		return errors.Wrapf(err, "Failed linking tee")
	}
	return nil
}

const (
	SYNC_FIFO_PATH    = "/syncfifo"
	SYNC_FIFO_CONTENT = "meshuggah rocks"
)

func emitFifoWaiter(file string) error {
	fifoWaiter := fmt.Sprintf(`#!/bin/sh
stat /syncfifo
echo "%s" | tee /syncfifo
exec $@
`, SYNC_FIFO_CONTENT)

	return ioutil.WriteFile(file, []byte(fifoWaiter), 0755)
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
	pidfile := ctx.String("pid-file")
	containerID := ctx.Args().Get(0)
	if len(containerID) == 0 {
		fmt.Fprintf(os.Stderr, "missing container ID\n")
		cli.ShowCommandHelpAndExit(ctx, "create", 1)
	}
	log.Infof("creating container %s", containerID)

	exists, err := containerExists(containerID)
	if err != nil {
		return errors.Wrap(err, "failed to check if container exists")
	}
	if exists {
		return fmt.Errorf("container '%s' already exists", containerID)
	}

	c, err := lxc.NewContainer(containerID, LXC_PATH)
	if err != nil {
		return errors.Wrap(err, "failed to create new container")
	}
	defer c.Release()

	spec, err := readBundleSpec(filepath.Join(ctx.String("bundle"), "config.json"))
	if err != nil {
		return errors.Wrap(err, "couldn't load bundle spec")
	}

	if err := os.MkdirAll(filepath.Join(LXC_PATH, containerID), 0770); err != nil {
		return errors.Wrap(err, "failed to create container dir")
	}

	if err := makeSyncFifo(filepath.Join(LXC_PATH, containerID)); err != nil {
		return errors.Wrap(err, "failed to make sync fifo")
	}

	if err := configureContainer(ctx, c, spec); err != nil {
		return errors.Wrap(err, "failed to configure container")
	}

	log.Infof("created syncfifo, executing %#v", spec.Process.Args)

	if err := startContainer(c, spec); err != nil {
		return errors.Wrap(err, "failed to start the container init")
	}

	if pidfile != "" {
		err := os.MkdirAll(path.Dir(pidfile), 0755)
		if err != nil {
			return errors.Wrapf(err, "Couldn't create pid file directory for %s", pidfile)
		}
		err = ioutil.WriteFile(pidfile, []byte(fmt.Sprintf("%d", c.InitPid())), 0755)
		if err != nil {
			return errors.Wrapf(err, "Couldn't create pid file %s", pidfile)
		}
	}

	log.Infof("created container %s in lxcdir %s", containerID, LXC_PATH)
	return nil
}

func configureContainerSecurity(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	// https://github.com/kubernetes/kubernetes/blob/a38a02792b55942177ee676a5e1993b18a8b4b0a/pkg/kubelet/apis/cri/runtime/v1alpha2/api.proto#L541
	//  // Privileged mode implies the following specific options are applied:
	// 1. All capabilities are added.
	// 2. Sensitive paths, such as kernel module paths within sysfs, are not masked.
	// 3. Any sysfs and procfs mounts are mounted RW.
	// 4. Apparmor confinement is not applied.
	// 5. Seccomp restrictions are not applied.
	// 6. The device cgroup does not restrict access to any devices.
	// 7. All devices from the host's /dev are available within the container.
	// 8. SELinux restrictions are not applied (e.g. label=disabled).
	// security
	// FIXME Kubelet does not set the 'io.kubernetes.cri-o.PrivilegedRuntime"
	// https://github.com/containers/podman/blob/8704b78a6fbb953acb6b74d1671d5ad6456bf81f/pkg/annotations/annotations.go#L64

	aaprofile := spec.Process.ApparmorProfile
	if aaprofile == "" {
		aaprofile = "generated"
	}
	if err := c.SetConfigItem("lxc.apparmor.profile", "generated"); err != nil {
		//if err := c.SetConfigItem("lxc.apparmor.profile", "unconfined"); err != nil {
		return errors.Wrapf(err, "faield to set apparmor.profile")
	}
	if aaprofile == "generated" {
		// TODO Create apparmor profile from spec.Linux.Readonly and MaskedPaths
		// set lxc.apparmor.raw
		// see man apparmor.d
	}

	if err := c.SetConfigItem("lxc.proc.oom_score_adj", fmt.Sprintf("%d", *spec.Process.OOMScoreAdj)); err != nil {
		return errors.Wrap(err, "failed to set lxc.proc.oom_score_adj")
	}

	if spec.Process.NoNewPrivileges {
		if err := c.SetConfigItem("lxc.no_new_privs", "1"); err != nil {
			return errors.Wrapf(err, "failed to set lxc.no_new_privs")
		}
	}

	return nil
}

func configureContainer(ctx *cli.Context, c *lxc.Container, spec *specs.Spec) error {
	if ctx.Bool("debug") {
		c.SetVerbosity(lxc.Verbose)
	}

	if err := configureLogging(ctx, c); err != nil {
		return errors.Wrap(err, "failed to configure logging")
	}

	// rootfs
	// todo Root.Readonly? - use lxc.rootfs.options
	if err := c.SetConfigItem("lxc.rootfs.path", spec.Root.Path); err != nil {
		return errors.Wrapf(err, "failed to set rootfs: '%s'", spec.Root.Path)
	}
	if err := c.SetConfigItem("lxc.rootfs.managed", "0"); err != nil {
		return errors.Wrap(err, "failed to set rootfs.managed to 0")
	}

	for _, envVar := range spec.Process.Env {
		if err := c.SetConfigItem("lxc.environment", envVar); err != nil {
			return fmt.Errorf("error setting environment variable '%s': %v", envVar, err)
		}
	}

	for _, ms := range spec.Mounts {
		// ignore cgroup mount, lxc automouts this even with lxc.rootfs.managed = 0
		// conf.c:mount_entry:1854 - Device or resource busy - Failed to mount "cgroup" on "/usr/lib/x86_64-linux-gnu/lxc/rootfs/sys/fs/cgroup"
		if ms.Type == "cgroup" {
			continue
		}

		// create target files and directories
		info, err := os.Stat(ms.Source)
		if err == nil {
			if info.IsDir() {
				ms.Options = append(ms.Options, "create=dir")
			} else {
				ms.Options = append(ms.Options, "create=file")
			}
		} else {
			// This case catches all kind of virtual and remote filesystems (/dev/pts, /dev/shm, sysfs, procfs, dev ...)
			// It can not be a file because the source file for a bind mount must exist.
			if os.IsNotExist(err) {
				ms.Options = append(ms.Options, "create=dir")
			} else {
				log.Debugf("failed to stat source %s of mountpoint %s: %s", ms.Source, ms.Destination, err)
			}
		}

		opts := strings.Join(ms.Options, ",")
		// Make mount paths relative to container root https://github.com/lxc/lxc/issues/2276
		dest := strings.TrimLeft(ms.Destination, "/")
		mnt := fmt.Sprintf("%s %s %s %s", ms.Source, dest, ms.Type, opts)

		if err := c.SetConfigItem("lxc.mount.entry", mnt); err != nil {
			return errors.Wrap(err, "failed to set mount config")
		}
	}

	mnt := fmt.Sprintf("%s %s none ro,bind,create=file", path.Join(LXC_PATH, c.Name(), SYNC_FIFO_PATH), strings.Trim(SYNC_FIFO_PATH, "/"))
	if err := c.SetConfigItem("lxc.mount.entry", mnt); err != nil {
		return errors.Wrap(err, "failed to set syncfifo mount config entry")
	}

	err := emitFifoWaiter(path.Join(spec.Root.Path, "fifo-wait"))
	if err != nil {
		return errors.Wrapf(err, "couldn't write wrapper init")
	}

	if err := ensureShell(spec.Root.Path); err != nil {
		return errors.Wrap(err, "couldn't ensure a shell exists in container")
	}

	if err := c.SetConfigItem("lxc.init.cwd", spec.Process.Cwd); err != nil {
		return errors.Wrap(err, "failed to set CWD")
	}

	if err := c.SetConfigItem("lxc.uts.name", spec.Hostname); err != nil {
		return errors.Wrap(err, "failed to set hostname")
	}

	argsString := "/fifo-wait " + strings.Join(spec.Process.Args, " ")
	if err := c.SetConfigItem("lxc.execute.cmd", argsString); err != nil {
		return errors.Wrap(err, "failed to set lxc.execute.cmd")

	}
	if err := c.SetConfigItem("lxc.hook.version", "1"); err != nil {
		return errors.Wrap(err, "failed to set hook version")
	}

	if err := configureNamespaces(c, spec); err != nil {
		return errors.Wrap(err, "failed to configure namespaces")
	}

	if ctx.Bool("systemd-cgroup") {
		c.SetConfigItem("lxc.cgroup.root", "system.slice")
	}

	if err := configureContainerSecurity(ctx, c, spec); err != nil {
		return errors.Wrap(err, "failed to configure container security")
	}

	// capabilities?

	// if !spec.Process.Terminal {
	// 	passFdsToContainer()
	// }

	// Write out final config file for debugging and use with lxc-attach:
	// Do not edit config after this.
	savedConfigFile := filepath.Join(LXC_PATH, c.Name(), "config")
	if err := c.SaveConfigFile(savedConfigFile); err != nil {
		return errors.Wrapf(err, "failed to save config file to '%s'", savedConfigFile)
	}

	return nil
}

func makeSyncFifo(dir string) error {
	fifoFilename := filepath.Join(dir, "syncfifo")
	prevMask := unix.Umask(0000)
	defer unix.Umask(prevMask)
	if err := unix.Mkfifo(fifoFilename, 0622); err != nil {
		return errors.Wrapf(err, "failed to make fifo '%s'", fifoFilename)
	}
	return nil
}

func waitContainer(c *lxc.Container, state lxc.State, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	// liblxc.Wait / go-libxc.Wait do not block when container is stopped. BUG in liblxc ?
	// https://github.com/lxc/lxc/issues/2027
	for time.Now().Before(deadline) {
		if c.State() == state {
			return true
		}
		time.Sleep(time.Millisecond * 50)
	}
	return false
}

func startContainer(c *lxc.Container, spec *specs.Spec) error {
	binary, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return err
	}

	cmd := exec.Command(
		binary,
		"internal",
		c.Name(),
		LXC_PATH,
		filepath.Join(LXC_PATH, c.Name(), "config"),
	)

	if !spec.Process.Terminal {
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	cmdErr := cmd.Start()

	log.Debugf("LXC container PID %d", c.InitPid())

	if cmdErr == nil {
		if !waitContainer(c, lxc.RUNNING, 30*time.Second) {
			cmdErr = fmt.Errorf("Container failed to initialize")
		}
	}

	return cmdErr
}
