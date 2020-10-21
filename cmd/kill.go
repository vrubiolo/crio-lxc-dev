// +build go1.10

package main

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"gopkg.in/lxc/go-lxc.v2"
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

const SIGZERO = unix.Signal(0)

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

func getSignal(ctx *cli.Context) (unix.Signal, error) {
	sig := ctx.Args().Get(1)
	if len(sig) == 0 {
		return SIGZERO, errors.New("missing signal")
	}

	// handle numerical signal value
	if num, err := strconv.Atoi(sig); err == nil {
		for _, signum := range signalMap {
			if num == int(signum) {
				return signum, nil
			}
		}
		return SIGZERO, fmt.Errorf("signal %s does not exist", sig)
	}

	// handle string signal value
	signum, exists := signalMap[sig]
	if !exists {
		return unix.Signal(0), fmt.Errorf("signal %s does not exist", sig)
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

	if err := clxc.SetConfigItem("lxc.signal.stop", strconv.Itoa(int(signum))); err != nil {
		return err
	}
	return clxc.Container.Stop()
}
