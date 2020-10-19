package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

	if err := c.Destroy(); err != nil {
		return errors.Wrap(err, "failed to delete container")
	}

	// left-over directories .lxc lxc.pivot
	if err := tryRemoveAllCgroupDir(c, "lxc.cgroup.dir"); err != nil {
		log.Warn().Err(err).Msg("remove lxc.cgroup.dir failed")
	}
	if err := tryRemoveAllCgroupDir(c, "lxc.cgroup.dir.container"); err != nil {
		log.Warn().Err(err).Msg("remove lxc.cgroup.dir.container failed")
	}
	//tryRemoveAllCgroupDir(c, "lxc.cgroup.dir.monitor")
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

func tryRemoveAllCgroupDir(c *lxc.Container, cfgName string) error {
	vals := c.ConfigItem(cfgName)
	if len(vals) < 1 || vals[0] == "" {
		return nil
	}

	dirName := filepath.Join("/sys/fs/cgroup", vals[0])
	log.Warn().Str("dirnName:", dirName).Msg("MARK")
	dir, err := os.Open(dirName)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	timer := time.NewTimer(time.Second * 3)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return fmt.Errorf("timeout killing processes")
		default:
			nprocs, err := killCgroupProcs(dirName)
			if err != nil {
				return err
			}
			if nprocs == 0 {
				break
			}
			time.Sleep(time.Millisecond * 10)
		}
	}
	// FIXME use 'crio-{containerName}.scope'  ?
	entries, err := dir.Readdir(-1)
	if err != nil {
		return err
	}
	// leftover lxc.pivot path
	for _, i := range entries {
		if i.IsDir() && i.Name() != "." && i.Name() != ".." {
			fullPath := filepath.Join(dirName, i.Name())
			log.Warn().Str("cgroup:", fullPath).Msg("MARK")
			if err := unix.Rmdir(fullPath); err != nil {
				return errors.Wrapf(err, "failed rmdir %s", fullPath)
			}
		}
	}
	return unix.Rmdir(dirName)
}

// getCgroupProcs returns the PIDs for all processes which are in the
// same control group as the process for which the PID is given.
// killing is hard https://lwn.net/Articles/754980/
func killCgroupProcs(scope string) (int, error) {
	cgroupProcsPath := filepath.Join(scope, "cgroup.procs")
	log.Debug().Str("path:", cgroupProcsPath).Msg("reading control group process list")
	procsData, err := ioutil.ReadFile(cgroupProcsPath)
	if err != nil {
		return -1, errors.Wrapf(err, "failed to read control group process list %s", cgroupProcsPath)
	}
	// cgroup.procs contains one PID per line and is newline separated.
	// A trailing newline is always present.
	s := strings.TrimSpace(string(procsData))
	if s == "" {
		return 0, nil
	}
	pidStrings := strings.Split(s, "\n")
	numPids := len(pidStrings)
	if numPids == 0 {
		return 0, nil
	}

	log.Warn().Strs("pids:", pidStrings).Str("cgroup:", scope).Msg("killing left-over container processes")

	for _, s := range pidStrings {
		pid, err := strconv.Atoi(s)
		if err != nil {
			// reading garbage from cgroup.procs should not happen
			return -1, errors.Wrapf(err, "failed to convert PID %q to number", s)
		}
		// make this process a session leader
		// and move all process to this session leader ?

		if err := unix.Kill(pid, 9); err != nil {
			return -1, errors.Wrapf(err, "failed to kill %d", pid)
		}
	}

	return numPids, nil
}
