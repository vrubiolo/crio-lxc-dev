package main

import (
	"fmt"
	"io/ioutil"
	stdlog "log"
	"os"
	"runtime"

	"github.com/apex/log"
	"github.com/urfave/cli"
	"gopkg.in/lxc/go-lxc.v2"
)

var (
	version     = ""
	debug       = false
	logFilePath = ""
)

func main() {
	app := cli.NewApp()
	app.Name = "crio-lxc"
	app.Usage = "crio-lxc is a CRI compliant runtime wrapper for lxc"
	app.Version = fmt.Sprintf("%s (%s) (lxc:%s)", version, runtime.Version(), lxc.Version())
	app.Commands = []cli.Command{
		stateCmd,
		createCmd,
		startCmd,
		killCmd,
		deleteCmd,
		execCmd,
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug mode",
		},
		cli.StringFlag{
			Name:  "log-level",
			Usage: "set log level for LXC",
		},
		cli.StringFlag{
			Name:  "log-file",
			Usage: "log file for LXC",
		},
		cli.StringFlag{
			Name:  "lxc-path, root",
			Usage: "set the lxc path to use",
			Value: "/var/lib/lxc",
		},
		cli.BoolFlag{
			Name:  "systemd-cgroup",
			Usage: "enable systemd cgroup",
		},
		cli.DurationFlag{
			Name:  "delete-wait",
			Usage: "number of seconds to wait before deleting container. to inspect container root for debugging purposes only.",
		},
		cli.StringFlag{
			Name:  "debug-dir",
			Usage: "Directory to save debugging information to.",
			Value: "/var/log/crio-lxc",
		},
	}

	log.SetLevel(log.InfoLevel)

	var logFile *os.File
	defer func() {
		if logFile != nil {
			err := logFile.Close()
			if err != nil {
				println(err.Error())
			}
		}
	}()

	app.Before = func(ctx *cli.Context) error {
		LXC_PATH = ctx.String("lxc-path")

		debug = ctx.Bool("debug")
		if debug {
			log.SetLevel(log.DebugLevel)
		}
		logFilePath = ctx.String("log-file")
		if logFilePath != "" {
			f, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640)
			if err != nil {
				log.Errorf("failed to open log file %s: %s", logFilePath, err)
			} else {
				logFile = f
				stdlog.SetOutput(logFile)
			}
		} else {
			// Only write to the specified log-file. If log-file is unsed discard output.
			// Writing to stderr is only allowed by OCI cmdline spec
			// if the command returns with an error.
			stdlog.SetOutput(ioutil.Discard)
		}
		log.Debugf("cmdline: %s", os.Args)
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Errorf("%+v", err)
		println(err.Error())
		os.Exit(1)
	}
}
