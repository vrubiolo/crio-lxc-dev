package main

import (
	"github.com/apex/log"
	"github.com/pkg/errors"
	"os"

	"github.com/urfave/cli/v2"
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
			EnvVars:     []string{"CRIO_LXC_LOG_FILE"},
			Destination: &clxc.LogFilePath,
		},
		// TODO this should be controlled by custom annotations / labels from within k8s
		// lxc-path-keep should be on the same fileystem as lxc-path
		&cli.StringFlag{
			Name:        "backup-dir",
			Usage:       "path to move container directory to when --backup-on-error is set",
			EnvVars:     []string{"CRIO_LXC_BACKUP_DIR"},
			Value:       "/var/lib/lxc-backup",
			Destination: &clxc.BackupDir,
		},
		&cli.BoolFlag{
			Name:        "backup-on-error",
			Usage:       "move container directory from lxc-path to this directory on error",
			EnvVars:     []string{"CRIO_LXC_BACKUP_ON_ERROR"},
			Value:       true,
			Destination: &clxc.BackupOnError,
		},
		&cli.StringFlag{
			Name:        "root",
			Aliases:     []string{"lxc-path"}, // 'root' is used by crio/conmon
			Usage:       "set the root path where container resources are created (logs, init and hook scripts). Must have access permissions",
			Value:       "/var/lib/lxc",
			Destination: &clxc.RuntimeRoot,
		},
		&cli.BoolFlag{
			Name:        "systemd-group",
			Usage:       "enable systemd cgroup",
			Destination: &clxc.SystemdCgroup,
		},
		&cli.StringFlag{
			Name:        "busybox-static",
			Usage:       "path to statically-linked busybox binary",
			EnvVars:     []string{"CRIO_LXC_BUSYBOX"},
			Value:       "/bin/busybox",
			Destination: &clxc.BusyboxBinary,
		},
		&cli.StringFlag{
			Name:        "start-cmd",
			Usage:       "(path to) crio-lxc-start",
			EnvVars:     []string{"CRIO_LXC_START_CMD"},
			Value:       "crio-lxc-start",
			Destination: &clxc.StartCommand,
		},
	}

	app.Before = func(ctx *cli.Context) error {
	  // The container ID is the first param of any sub command
		containerID := ctx.Args().Get(1)
		if len(containerID) == 0 {
			return errors.New("missing container ID")
		}
		clxc.ContainerID = containerID
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		//log.Debugf("cmdline: %s", os.Args)
		log.Errorf("%+v", err)
		println(err.Error())
		clxc.Release()
		os.Exit(1)
	}
}
