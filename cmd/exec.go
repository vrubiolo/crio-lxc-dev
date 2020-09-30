package main

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"golang.org/x/sys/unix"

	lxc "gopkg.in/lxc/go-lxc.v2"
)

var execCmd = cli.Command{
	Name:      "exec",
	Usage:     "execute a new process in a running container",
	ArgsUsage: "<containerID>",
	Action:    doExec,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "process",
			Aliases: []string{"p"},
			Usage: "path to process json",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "pid-file",
			Usage: "file to write the process id to",
			Value: "",
		},
		&cli.BoolFlag{
			Name:  "detach",
			Aliases: []string{"d"},
			Usage: "detach from the executed process",
		},
	},
}

// NOTE stdio (stdout/stderr) is not attached when adding unix.CLONE_NEWUSER
const EXEC_NAMESPACES = unix.CLONE_NEWIPC | unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP | unix.CLONE_NEWPID

func doExec(ctx *cli.Context) error {
	err := clxc.LoadContainer()
	if err != nil {
		return errors.Wrap(err, "failed to load container")
	}
	c := clxc.Container

	attachOpts := lxc.AttachOptions{
		Namespaces: EXEC_NAMESPACES,
	}

	var procArgs []string
	specFilePath := ctx.String("process")

	log.Debug().Str("spec:", specFilePath).Msg("read process spec")
	specData, err := ioutil.ReadFile(specFilePath)
	log.Trace().Err(err).RawJSON("spec", specData).Msg("process spec data")

	if err == nil {
		// prefer the process spec file
		var procSpec *specs.Process
		err := json.Unmarshal(specData, &procSpec)
		if err != nil {
			return errors.Wrapf(err, "failed to read process spec")
		}
		// tanslate process spec to lxc.AttachOptions
		procArgs = procSpec.Args
		attachOpts.UID = int(procSpec.User.UID)
		attachOpts.GID = int(procSpec.User.GID)
		attachOpts.Cwd = procSpec.Cwd
		// Do not inherit the parent process environment
		attachOpts.ClearEnv = true
		attachOpts.Env = procSpec.Env
	} else {
		// fall back to cmdline arguments
		if ctx.Args().Len() >= 2 {
			procArgs = ctx.Args().Slice()[1:]
		}
	}

	attachOpts.StdinFd = os.Stdin.Fd()
	attachOpts.StdoutFd = os.Stdout.Fd()
	attachOpts.StderrFd = os.Stderr.Fd()

	detach := ctx.Bool("detach")
	log.Debug().Bool("detach", detach).Strs("args", procArgs).Msg("exec cmd")

	if detach {
		pidFile := ctx.String("pid-file")
		pid, err := c.RunCommandNoWait(procArgs, attachOpts)
		log.Debug().Err(err).Int("pid", pid).Msg("cmd executed detached")
		if err != nil {
			return errors.Wrapf(err, "c.RunCommandNoWait failed")
		}
		if pidFile == "" {
			log.Warn().Msg("detaching process but pid-file value is empty")
			return nil
		}
		return createPidFile(pidFile, pid)
	} else {
		exitStatus, err := c.RunCommandStatus(procArgs, attachOpts)
		log.Debug().Err(err).Int("exit", exitStatus).Msg("cmd executed synchronous")
		if err != nil {
			return errors.Wrapf(err, "Cmd returned with exit code %d", exitStatus)
		}
	}
	return nil
}
