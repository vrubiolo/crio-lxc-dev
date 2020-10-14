// Allow Setns to be called safely
// https://github.com/vishvananda/netns/issues/17
// +build go1.10

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	lxc "gopkg.in/lxc/go-lxc.v2"
)

var killCmd = cli.Command{
	Name:   "kill",
	Usage:  "sends a signal to a container",
	Action: doKill,
	ArgsUsage: `[containerID] [signal]

<containerID> is the ID of the container to send a signal to
[signal] name (without SIG) or signal num ?
`,
}
var signalMap = map[string]unix.Signal{
	"ABRT":   unix.SIGABRT,
	"ALRM":   unix.SIGALRM,
	"BUS":    unix.SIGBUS,
	"CHLD":   unix.SIGCHLD,
	"CLD":    unix.SIGCLD,
	"CONT":   unix.SIGCONT,
	"FPE":    unix.SIGFPE,
	"HUP":    unix.SIGHUP,
	"ILL":    unix.SIGILL,
	"INT":    unix.SIGINT,
	"IO":     unix.SIGIO,
	"IOT":    unix.SIGIOT,
	"KILL":   unix.SIGKILL,
	"PIPE":   unix.SIGPIPE,
	"POLL":   unix.SIGPOLL,
	"PROF":   unix.SIGPROF,
	"PWR":    unix.SIGPWR,
	"QUIT":   unix.SIGQUIT,
	"SEGV":   unix.SIGSEGV,
	"STKFLT": unix.SIGSTKFLT,
	"STOP":   unix.SIGSTOP,
	"SYS":    unix.SIGSYS,
	"TERM":   unix.SIGTERM,
	"TRAP":   unix.SIGTRAP,
	"TSTP":   unix.SIGTSTP,
	"TTIN":   unix.SIGTTIN,
	"TTOU":   unix.SIGTTOU,
	"URG":    unix.SIGURG,
	"USR1":   unix.SIGUSR1,
	"USR2":   unix.SIGUSR2,
	"VTALRM": unix.SIGVTALRM,
	"WINCH":  unix.SIGWINCH,
	"XCPU":   unix.SIGXCPU,
	"XFSZ":   unix.SIGXFSZ,
}

// Retrieve the PID from container init process safely.
// This is not required when lxc uses pidfd internally
func safeGetInitPid(c *lxc.Container) (int, *os.File, error) {
	pid := c.InitPid()
	if pid < 0 {
		return -1, nil, fmt.Errorf("expected init pid > 0, but was %d", pid)
	}
	// Open the proc directory of the init process to avoid that
	// it's PID is recycled before it receives the signal.
	proc, err := os.Open(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		// This may fail if either the proc filesystem is not mounted, or
		// the process has died
		fmt.Fprintf(os.Stderr, "failed to open /proc/%d : %s", pid, err)
	}
	// double check that the init process still exists, and the proc
	// directory actually belongs to the init process.
	pid2 := c.InitPid()
	if pid2 != pid {
		proc.Close()
		return -1, nil, errors.Wrapf(err, "init process %d has already died", pid)
	}
	return pid, proc, nil
}

// getCgroupProcs returns the PIDs for all processes which are in the
// same control group as the process for which the PID is given.
func getCgroupProcs(pid int) ([]int, error) {
	procCgroup := fmt.Sprintf("/proc/%d/cgroup", pid)

	data, err := ioutil.ReadFile(procCgroup)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read %s", procCgroup)
	}
	// see 'man 7 cgroups #/proc files'
	// for cgroup2 unified hierarchy the format is '0::{path relative to cgroup mount}'
	parts := strings.SplitN(string(data), ":", 3)
	if len(parts) != 3 {
		return nil, errors.Wrapf(err, "unsupported proc cgroup format: %s", data)
	}
	if parts[0] != "0" {
		return nil, fmt.Errorf("expected cgroups 2 identifier in cgroup file: %s", data)
	}

	cgroupPath := strings.TrimSpace(parts[2])
	cgroupProcsPath := filepath.Join("/sys/fs/cgroup", cgroupPath, "cgroup.procs")
	log.Debug().Str("path:", cgroupProcsPath).Msg("reading control group process list")
	procsData, err := ioutil.ReadFile(cgroupProcsPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read control group process list %s", cgroupProcsPath)
	}
	// cgroup.procs contains one PID per line and is newline separated.
	// A trailing newline is always present.
	pidStrings := strings.Split(strings.TrimSpace(string(procsData)), "\n")
	if len(pidStrings) == 0 {
		log.Warn().Msg("cgroup.procs is empty - it should contain at least the init process PID?")
		return nil, nil
	}

	pids := make([]int, 0, len(pidStrings))
	for _, s := range pidStrings {
		pid, err := strconv.Atoi(s)
		if err != nil {
			// reading garbage from cgroup.procs should not happen
			return nil, errors.Wrapf(err, "failed to convert PID %q to number", s)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func killContainer(c *lxc.Container, signum unix.Signal) error {
	// try to freeze the container to get a 'stable' view of the cgroup processes
	err := c.Freeze()
	if err != nil {
		log.Warn().Msg("failed to freeze container")
	} else {
		defer c.Unfreeze()
	}
	pid := c.InitPid()
	if pid < 1 {
		return fmt.Errorf("expected init pid > 0, but was %d", pid)
	}
	log.Debug().Int("pid:", pid).Msg("container init PID")
	pids, err := getCgroupProcs(pid)
	if err != nil {
		return err
	}
	log.Debug().Ints("pids:", pids).Str("sig:", signum.String()).Msg("killing container processes")
	for _, pid := range pids {
		if err := unix.Kill(pid, signum); err != nil {
			return errors.Wrapf(err, "failed to send signum:%d(%s)", signum, signum)
		}
	}
	return nil
}

func getSignal(ctx *cli.Context) (unix.Signal, error) {
	sig := ctx.Args().Get(1)
	if len(sig) == 0 {
		return unix.SIGCONT, errors.New("missing signal")
	}

	// handle numerical signal value
	if num, err := strconv.Atoi(sig); err == nil {
		for _, signum := range signalMap {
			if num == int(signum) {
				return signum, nil
			}
		}
		return unix.SIGCONT, fmt.Errorf("signal %s does not exist", sig)
	}

	// handle string signal value
	signum, exists := signalMap[sig]
	if !exists {
		return unix.SIGCONT, fmt.Errorf("signal %s does not exist", sig)
	}
	return signum, nil
}

func doKill(ctx *cli.Context) error {
	err := clxc.LoadContainer()
	if err != nil {
		return errors.Wrap(err, "failed to load container")
	}

	if !clxc.Container.Running() {
		return fmt.Errorf("container is not running")
	}

	signum, err := getSignal(ctx)
	if err != nil {
		return errors.Wrap(err, "invalid signal param")
	}

	return killContainer(clxc.Container, signum)
}
