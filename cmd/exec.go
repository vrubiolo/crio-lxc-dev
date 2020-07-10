package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

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

func doExec(ctx *cli.Context) error {
	containerID := ctx.Args().First()
	if len(containerID) == 0 {
		fmt.Fprintf(os.Stderr, "missing container ID\n")
		cli.ShowCommandHelpAndExit(ctx, "exec", 1)
	}

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

	if ctx.Bool("detach") {
		// FIXME detach is not called by conmon ! why ?
		pid, err := c.RunCommandNoWait(procArgs, attachOpts)
		pidFile := ctx.String("pid-file")
		err = ioutil.WriteFile(pidFile, []byte(fmt.Sprintf("%s\n", pid)), 0640)
		if err != nil {
			return errors.Wrapf(err, "failed to write pid file %s: %s", pidFile)
		}
	} else {
		exitStatus, err := c.RunCommandStatus(procArgs, attachOpts)
		if err != nil {
			return errors.Wrapf(err, "Cmd returned with exit code %d", exitStatus)
		}
	}
	return nil
}
