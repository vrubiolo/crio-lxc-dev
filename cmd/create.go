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
	"github.com/segmentio/ksuid"
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
echo "%s" | tee /syncfifo
echo "Sourcing command file $1"
echo "-----------------------"
cat $1
echo "-----------------------"
. $1
`, SYNC_FIFO_CONTENT)

	return ioutil.WriteFile(file, []byte(fifoWaiter), 0755)
}

// Write the container init command to a file.
// This file is then sourced by the file /syncfifo on container startup.
// Every command argument is quoted so `exec` can process them properly.
func emitCmdFile(cmdFile string, args ...string) error {
	// https://stackoverflow.com/questions/33887194/how-to-set-multiple-commands-in-one-yaml-file-with-kubernetes
	buf := strings.Builder{}
	buf.WriteString("exec")
	for _, arg := range args {
		buf.WriteRune(' ')
		buf.WriteRune('"')
		buf.WriteString(arg)
		buf.WriteRune('"')
	}
	return ioutil.WriteFile(cmdFile, []byte(buf.String()), 0640)
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
	aaprofile := spec.Process.ApparmorProfile
	if aaprofile == "" {
		aaprofile = "generated"
	}
	if err := c.SetConfigItem("lxc.apparmor.profile", aaprofile); err != nil {
		return errors.Wrapf(err, "failed to set apparmor.profile to %s", aaprofile)
	}
	if aaprofile == "generated" {
		// TODO Create apparmor profile from the spec (honoring Linux.Readonly and Linux.MaskedPaths)
		// see man apparmor.d
		//	if err := c.SetConfigItem("lxc.apparmor.raw", aaprofile); err != nil {
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

	// crio deletes the working directory so lxc should not do this itself
	//if err := c.SetConfigItem("lxc.ephemeral", "1"); err != nil {
	//	return errors.Wrapf(err, "failed to set lxc.ephemeral")
	//}

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
			// It can never be a file because the source file for a bind mount must exist.
			if os.IsNotExist(err) {
				ms.Options = append(ms.Options, "create=dir")
			} else {
				log.Debugf("failed to stat source %s of mountpoint %s: %s", ms.Source, ms.Destination, err)
			}
		}
		opts := strings.Join(ms.Options, ",")

		mountDest, err := resolveMountDestination(spec.Root.Path, ms.Destination)
		if err != nil {
			log.Debugf("resolveMountDestination: %s --> %s (err:%s)", ms.Destination, mountDest, err)
		} else {
			log.Debugf("resolveMountDestination: %s --> %s)", ms.Destination, mountDest)
		}

		mnt := fmt.Sprintf("%s %s %s %s", ms.Source, mountDest, ms.Type, opts)
		log.Debugf("adding mount entry %q", mnt)

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

	cmd := fmt.Sprintf("/mycmd.%s", ksuid.New().String())
	err = emitCmdFile(path.Join(spec.Root.Path, cmd), spec.Process.Args...)
	if err != nil {
		return errors.Wrapf(err, "could not write command file")
	}

	if err := c.SetConfigItem("lxc.execute.cmd", "/fifo-wait "+cmd); err != nil {
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
