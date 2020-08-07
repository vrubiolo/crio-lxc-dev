package main

import (
	"fmt"
	stdlog "log"
	"os"

	"github.com/apex/log"
	"github.com/urfave/cli"
)

var (
	version = ""
	debug   = false
)

func main() {
	app := cli.NewApp()
	app.Name = "crio-lxc"
	app.Usage = "crio-lxc is a CRI compliant runtime wrapper for lxc"
	app.Version = version
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
		logFilePath := ctx.String("log-file")
		if logFilePath != "" {
			f, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640)
			if err != nil {
				log.Errorf("failed to open log file %s: %s", logFilePath, err)
			} else {
				logFile = f
				stdlog.SetOutput(logFile)
			}
		}
		log.Debugf("LXC_PATH: %s", LXC_PATH)
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		format := "error: %v\n"
		if debug {
			format = "error: %+v\n"
		}
		log.Errorf("Cmdline: %s\nerror: %+v\n", os.Args, err)
		fmt.Fprintf(os.Stderr, format, err)
		os.Exit(1)
	}
}
