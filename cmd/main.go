package main

import (
	"fmt"
	"github.com/pkg/errors"
	"os"

	"github.com/urfave/cli/v2"
)

const (
	CURRENT_OCI_VERSION = "0.2.1"
)

var version string
var clxc CrioLXC

func main() {
	app := cli.NewApp()
	app.Name = "crio-lxc"
	app.Usage = "crio-lxc is a CRI compliant runtime wrapper for lxc"
	app.Version = clxc.VersionString()
	app.Commands = []*cli.Command{
		&stateCmd,
		&createCmd,
		&startCmd,
		&killCmd,
		&deleteCmd,
		&execCmd,
	}

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "log-level",
			Usage:       "set log level (trace|debug|info|warn|error)",
			EnvVars:     []string{"CRIO_LXC_LOG_LEVEL"},
			Value:       "error",
			Destination: &clxc.LogLevelString,
		},
		&cli.StringFlag{
			Name:        "log-file",
			Usage:       "log file for LXC and crio-lxc (default is per container in lxc-path)",
			EnvVars:     []string{"CRIO_LXC_LOG_FILE", "LOG_FILE"},
			Value:       "/var/log/crio-lxc.log",
			Destination: &clxc.LogFilePath,
		},
		// TODO this should be controlled by custom annotations / labels from within k8s
		// lxc-path-keep should be on the same fileystem as lxc-path
		&cli.StringFlag{
			Name:        "backup-dir",
			Usage:       "directory for container runtime directory backups",
			EnvVars:     []string{"CRIO_LXC_BACKUP_DIR"},
			Value:       "/var/lib/lxc-backup",
			Destination: &clxc.BackupDir,
		},
		&cli.BoolFlag{
			Name:        "backup-on-error",
			Usage:       "backup container runtime directory when start-cmd fails",
			EnvVars:     []string{"CRIO_LXC_BACKUP_ON_ERROR"},
			Value:       true,
			Destination: &clxc.BackupOnError,
		},
		// backup any container started (e.g to inspect failing init commands)
		&cli.BoolFlag{
			Name:        "backup",
			Usage:       "backup the container runtime before start-cmd is called",
			EnvVars:     []string{"CRIO_LXC_BACKUP"},
			Value:       false,
			Destination: &clxc.Backup,
		},
		&cli.StringFlag{
			Name:        "root",
			Aliases:     []string{"lxc-path"}, // 'root' is used by crio/conmon
			Usage:       "set the root path where container resources are created (logs, init and hook scripts). Must have access permissions",
			Value:       "/var/lib/lxc",
			Destination: &clxc.RuntimeRoot,
		},
		&cli.BoolFlag{
			Name:        "systemd-cgroup",
			Usage:       "enable systemd cgroup",
			Destination: &clxc.SystemdCgroup,
		},
		&cli.StringFlag{
			Name:        "cmd-init",
			Usage:       "Absolute path to container init binary (crio-lxc-init)",
			EnvVars:     []string{"CRIO_LXC_CMD_INIT"},
			Value:       "/usr/local/bin/crio-lxc-init",
			Destination: &clxc.InitCommand,
		},
		&cli.StringFlag{
			Name:        "cmd-start",
			Usage:       "Name or path to container start binary (crio-lxc-start)",
			EnvVars:     []string{"CRIO_LXC_CMD_START"},
			Value:       "crio-lxc-start",
			Destination: &clxc.StartCommand,
		},
		&cli.StringFlag{
			Name:        "cmd-hook",
			Usage:       "Name or path to container hook binary (crio-lxc-hook)",
			EnvVars:     []string{"CRIO_LXC_CMD_HOOK"},
			Value:       "crio-lxc-hook",
			Destination: &clxc.HookCommand,
		},
	}

	app.Before = func(ctx *cli.Context) error {
		clxc.Command = ctx.Args().Get(0)
		return nil
	}

	setupCmd := func(ctx *cli.Context) error {
		containerID := ctx.Args().Get(0)
		if len(containerID) == 0 {
			return errors.New("missing container ID")
		}
		clxc.ContainerID = containerID
		clxc.Command = ctx.Command.Name

		if err := clxc.configureLogging(); err != nil {
			return err
		}

		log.Info().Strs("args", os.Args).Msg("run cmd")
		return nil
	}

	// Disable the default error messages for cmdline errors.
	// By default the app/cmd help is printed to stdout, which is not required hen called from cri-o.
	// Instead the cmdline is reflected to identify cmdline interface errors
	errUsage := func(context *cli.Context, err error, isSubcommand bool) error {
		fmt.Fprintf(os.Stderr, "usage error %s: %s\n", err, os.Args)
		return err
	}

	app.OnUsageError = errUsage

	for _, cmd := range app.Commands {
		cmd.Before = setupCmd
		cmd.OnUsageError = errUsage
	}

	app.CommandNotFound = func(ctx *cli.Context, cmd string) {
		fmt.Fprintf(os.Stderr, "undefined subcommand %q cmdline%s\n", cmd, os.Args)
	}

	err := app.Run(os.Args)
	log.Info().Err(err).Msg("done")
	clxc.Release()
	if err != nil {
		// write diagnostics message to stderr for crio/kubelet
		println(err.Error())
		os.Exit(1)
	}
}
