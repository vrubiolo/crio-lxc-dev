package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"golang.org/x/sys/unix"

	lxc "gopkg.in/lxc/go-lxc.v2"
)

var execCmd = cli.Command{
	Name:      "exec",
	Usage:     "execute a new process in a running container",
	ArgsUsage: "<containerID>",
	Action:    doExec,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "process, p",
			Usage: "path to process json",
			Value: "",
		},
		cli.StringFlag{
			Name:  "pid-file",
			Usage: "file to write the process id to",
			Value: "",
		},
		cli.BoolFlag{
			Name:  "detach, d",
			Usage: "detach from the executed process",
		},
	},
}

// NOTE stdio (stdout/stderr) is not attached when adding unix.CLONE_NEWUSER
const EXEC_NAMESPACES = unix.CLONE_NEWIPC | unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP | unix.CLONE_NEWPID

func debugf(ctx *cli.Context, format string, args ...interface{}) {
	if ctx.Bool("debug") {
		if !strings.HasSuffix(format, "\n") {
			format += "\n"
		}
		fmt.Fprintf(os.Stderr, "debug "+format, args...)
	}
}

func doExec(ctx *cli.Context) error {
	containerID := ctx.Args().First()
	if len(containerID) == 0 {
		return fmt.Errorf("missing container ID")
		cli.ShowCommandHelpAndExit(ctx, "exec", 1)
	}

	debugf(ctx, "exec in container %s", containerID)

	c, err := lxc.NewContainer(containerID, LXC_PATH)
	if err != nil {
		return errors.Wrap(err, "failed to create new container")
	}
	defer c.Release()

	attachOpts := lxc.AttachOptions{
		Namespaces: EXEC_NAMESPACES,
	}

	var procArgs []string
	specFilePath := ctx.String("process")
	debugf(ctx, "reading process spec %s", specFilePath)
	specData, err := ioutil.ReadFile(specFilePath)
	if err == nil {
		// prefer the process spec file
		var procSpec *specs.Process
		err := json.Unmarshal(specData, &procSpec)
		if err != nil {
			return errors.Wrapf(err, "failed to read process spec from %s: %s", specFilePath, err)
		}
		// tanslate process spec to lxc.AttachOptions
		procArgs = procSpec.Args
		attachOpts.UID = int(procSpec.User.UID)
		attachOpts.GID = int(procSpec.User.GID)
		attachOpts.Cwd = procSpec.Cwd
		attachOpts.Env = procSpec.Env
	} else {
		// fall back to cmdline arguments
		if len(ctx.Args()) >= 2 {
			procArgs = ctx.Args()[1:]
		}
	}

	debugf(ctx, "process setup completed %v: %#v", procArgs, attachOpts)

	attachOpts.StdinFd = os.Stdin.Fd()
	attachOpts.StdoutFd = os.Stdout.Fd()
	attachOpts.StderrFd = os.Stderr.Fd()

	if ctx.Bool("detach") {
		pidFile := ctx.String("pid-file")
		debugf(ctx, "detaching process")
		pid, err := c.RunCommandNoWait(procArgs, attachOpts)
		if err != nil {
			return errors.Wrapf(err, "c.RunCommandNoWait failed")
		}
		if pidFile == "" {
			debugf(ctx, "detaching process but pid-file value is empty")
			return nil
		}
		return createPidFile(pidFile, pid)
	} else {
		debugf(ctx, "run command synchronous")
		exitStatus, err := c.RunCommandStatus(procArgs, attachOpts)
		if err != nil {
			return errors.Wrapf(err, "Cmd returned with exit code %d", exitStatus)
		}
	}
	return nil
}
