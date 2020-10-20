package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	api "github.com/lxc/crio-lxc/clxc"
	lxc "gopkg.in/lxc/go-lxc.v2"
)

var execCmd = cli.Command{
	Name:      "exec",
	Usage:     "execute a new process in a running container",
	ArgsUsage: "<containerID>",
	Action:    doExec,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "process",
			Aliases: []string{"p"},
			Usage:   "path to process json",
			Value:   "",
		},
		&cli.StringFlag{
			Name:  "pid-file",
			Usage: "file to write the process id to",
			Value: "",
		},
		&cli.BoolFlag{
			Name:    "detach",
			Aliases: []string{"d"},
			Usage:   "detach from the executed process",
		},
	},
}

func doExec(ctx *cli.Context) error {
	err := clxc.LoadContainer()
	if err != nil {
		return errors.Wrap(err, "failed to load container")
	}
	c := clxc.Container

	attachOpts := lxc.AttachOptions{}

	var procArgs []string
	specFilePath := ctx.String("process")

	if specFilePath != "" {
		log.Debug().Str("spec:", specFilePath).Msg("read process spec")
		specData, err := ioutil.ReadFile(specFilePath)
		log.Trace().Err(err).RawJSON("spec", specData).Msg("process spec data")

		if err != nil {
			return errors.Wrap(err, "failed to read process spec")
		}

		var procSpec *specs.Process
		err = json.Unmarshal(specData, &procSpec)
		if err != nil {
			return errors.Wrapf(err, "failed to unmarshal process spec")
		}
		// tanslate process spec to lxc.AttachOptions
		procArgs = procSpec.Args
		attachOpts.UID = int(procSpec.User.UID)
		attachOpts.GID = int(procSpec.User.GID)
		attachOpts.Cwd = procSpec.Cwd
		// Do not inherit the parent process environment
		attachOpts.ClearEnv = true
		attachOpts.Env = procSpec.Env

		/* FIXME handlevalues not supported by go-lxc ?
		   // Capabilities are Linux capabilities that are kept for the process.
		   Capabilities *LinuxCapabilities `json:"capabilities,omitempty" platform:"linux"`
		   // Rlimits specifies rlimit options to apply to the process.
		   Rlimits []POSIXRlimit `json:"rlimits,omitempty" platform:"linux,solaris"`
		   // NoNewPrivileges controls whether additional privileges could be gained by processes in the container.
		   NoNewPrivileges bool `json:"noNewPrivileges,omitempty" platform:"linux"`
		   // ApparmorProfile specifies the apparmor profile for the container.
		   ApparmorProfile string `json:"apparmorProfile,omitempty" platform:"linux"`
		   // Specify an oom_score_adj for the container.
		   OOMScoreAdj *int `json:"oomScoreAdj,omitempty" platform:"linux"`
		   // SelinuxLabel specifies the selinux context that the container process is run as.
		   SelinuxLabel str
		*/

	} else {
		// fall back to cmdline arguments
		if ctx.Args().Len() >= 2 {
			procArgs = ctx.Args().Slice()[1:]
		}
		// FIXME load container config to determine supported namespaces ?
	}

	spec, err := api.ReadSpec(clxc.RuntimePath(api.INIT_SPEC))
	if err != nil {
		return errors.Wrap(err, "failed to read container runtime spec")
	}

	// get namespaces
	for _, ns := range spec.Linux.Namespaces {
		n, supported := NamespaceMap[ns.Type]
		if !supported {
			return fmt.Errorf("can not attach to namespace %s: unsupported namespace", ns.Type)
		}
		attachOpts.Namespaces |= n.CloneFlag
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
