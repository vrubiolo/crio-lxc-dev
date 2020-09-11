// Allow Setns to be called safely
// https://github.com/vishvananda/netns/issues/17
// +build go1.10

package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/apex/log"
	"github.com/pkg/errors"
	"github.com/urfave/cli"

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

// PidfdSendSignal uses the kernel pidfd API to send signals to process without race conditions.
// This requires at least kernel version 5.8.0 for setns() to support pidfd descriptors.
// see 'man 2 setns', 'man 2 pidfd_send_signal'
func PidfdSendSignal(pidfd uintptr, signum unix.Signal) error {
	// the runtime OS thread must be locked to safely enter namespaces.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// setns with pidfd requires at least kernel version 5.8.0
	err := unix.Setns(int(pidfd), unix.CLONE_NEWPID)
	if err != nil {
		return err
	}
	// pifd_send_signal was introduced in kernel version 5.3
	_, _, e1 := unix.Syscall(unix.SYS_PIDFD_SEND_SIGNAL, pidfd, uintptr(signum), 0)
	if e1 != 0 {
		return e1
	}
	return nil
}

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
		log.Warnf("failed to open /proc/%d : %s", err)
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

func killContainer(c *lxc.Container, signum unix.Signal) error {
	pid, proc, err := safeGetInitPid(c)
	if err != nil {
		return err
	}
	if proc != nil {
		defer proc.Close()
	}
	log.Debugf("kill pid:%d signum:%d(%s)", pid, signum, signum)
	if err := unix.Kill(pid, signum); err != nil {
		return errors.Wrapf(err, "failed to send signal")
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
	containerID := ctx.Args().Get(0)
	if len(containerID) == 0 {
		return errors.New("missing container ID")
	}
	exists, err := containerExists(containerID)
	if err != nil {
		return errors.Wrap(err, "failed to check if container exists")
	}
	if !exists {
		return fmt.Errorf("container '%s' not found", containerID)
	}

	c, err := lxc.NewContainer(containerID, LXC_PATH)
	if err != nil {
		return errors.Wrap(err, "failed to load container")
	}
	defer c.Release()

	if err := configureLogging(ctx, c); err != nil {
		return errors.Wrap(err, "failed to configure logging")
	}

	if !c.Running() {
		return fmt.Errorf("container '%s' is not running", containerID)
	}

	signum, err := getSignal(ctx)
	if err != nil {
		return errors.Wrap(err, "invalid signal param")
	}

	/*
		r, err := LinuxRelease()
		if err != nil {
			log.Errorf("failed to detect linux release: %s", err)
		}

		if err == nil && r.GreaterEqual(5, 8, 0) {
			pidfd, err := c.InitPidFd()
			if err != nil {
				return err
			}
			defer pidfd.Close()
			log.Debugf("pidfd_send_signal pidfd:%d signum:%d(%s)", pidfd, signum, signum)
			return PidfdSendSignal(pidfd.Fd(), signum)
		} else {
	*/
	return killContainer(c, signum)
	//}
	return nil
}
