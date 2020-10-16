package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"golang.org/x/sys/unix"
	lxc "gopkg.in/lxc/go-lxc.v2"
)

var deleteCmd = cli.Command{
	Name:   "delete",
	Usage:  "deletes a container",
	Action: doDelete,
	ArgsUsage: `[containerID]

<containerID> is the ID of the container to delete
`,
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "force",
			Usage: "force deletion",
		},
	},
}

func doDelete(ctx *cli.Context) error {
	err := clxc.LoadContainer()
	if err == ErrContainerNotExist && ctx.Bool("force") {
		return nil
	}
	if err != nil {
		return err
	}
	c := clxc.Container

	state := c.State()
	if state != lxc.STOPPED {
		if !ctx.Bool("force") {
			return fmt.Errorf("container must be stopped before delete (current state is %s)", state)
		}

		if err := c.Stop(); err != nil {
			return errors.Wrap(err, "failed to stop container")
		}
	}

	if vals := c.ConfigItem("lxc.cgroup.dir"); len(vals) > 0 {
		if err := cleanupCgroupDir(vals[0]); err != nil {
			return errors.Wrap(err, "failed to delete lxc.cgroup.dir")
		}
	} else {
		if vals := c.ConfigItem("lxc.cgroup.dir.container"); len(vals) > 0 {
			if err := cleanupCgroupDir(vals[0]); err != nil {
				return errors.Wrap(err, "failed to delete lxc.cgroup.dir.container")
			}
		}
		if vals := c.ConfigItem("lxc.cgroup.dir.monitor"); len(vals) > 0 {
			if err := cleanupCgroupDir(vals[0]); err != nil {
				return errors.Wrap(err, "failed to delete lxc.cgroup.dir.monitor")
			}
		}
	}

	if err := c.Destroy(); err != nil {
		return errors.Wrap(err, "failed to delete container")
	}

	// load spec
	/*
		spec, err := clxc.ReadSpec(clxc.RuntimePath(clxc.INIT_SPEC))
		if err != nil {
		  return errors.Wrap(err, "failed to load runtime spec")
			panic(err)
		}
	*/

	// "Note that resources associated with the container,
	// but not created by this container, MUST NOT be deleted."

	// TODO - because we set rootfs.managed=0, Destroy() doesn't
	// delete the /var/lib/lxc/$containerID/config file:
	return os.RemoveAll(clxc.RuntimePath())
}

func cleanupCgroupDir(dirName string) error {
	dir, err := os.Open(dirName)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// FIXME use 'crio-{containerName}.scope'  ?
	entries, err := dir.Readdir(-1)
	if err != nil {
		return err
	}
	for _, i := range entries {
		if i.IsDir() {
			fullPath := filepath.Join(dirName, i.Name())
			if err := killCgroupProcs(fullPath); err != nil {
				return err
			}
			if err := unix.Rmdir(fullPath); err != nil {
				return err
			}
		}
	}
	return unix.Rmdir(dirName)
}

// getCgroupProcs returns the PIDs for all processes which are in the
// same control group as the process for which the PID is given.
func killCgroupProcs(scope string) error {
	cgroupProcsPath := filepath.Join(scope, "cgroup.procs")
	log.Debug().Str("path:", cgroupProcsPath).Msg("reading control group process list")
	procsData, err := ioutil.ReadFile(cgroupProcsPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read control group process list %s", cgroupProcsPath)
	}
	// cgroup.procs contains one PID per line and is newline separated.
	// A trailing newline is always present.
	pidStrings := strings.Split(strings.TrimSpace(string(procsData)), "\n")
	if len(pidStrings) == 0 {
		log.Warn().Msg("cgroup.procs is empty - it should contain at least the init process PID?")
		return nil
	}

	for _, s := range pidStrings {
		pid, err := strconv.Atoi(s)
		if err != nil {
			// reading garbage from cgroup.procs should not happen
			return errors.Wrapf(err, "failed to convert PID %q to number", s)
		}
		if err := unix.Kill(pid, 9); err != nil {
			return errors.Wrapf(err, "failed to kill %d", pid)
		}
	}
	return nil
}
