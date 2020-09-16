package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"time"
)

var startCmd = cli.Command{
	Name:   "start",
	Usage:  "starts a container",
	Action: doStart,
	ArgsUsage: `[containerID]

starts <containerID>
`,
	Flags: []cli.Flag{
		cli.DurationFlag{
			Name:  "syncfifo-timeout",
			Usage: "timeout for reading from syncfifo ",
			Value: time.Second * 5,
		},
	},
}

func doStart(ctx *cli.Context) error {
	containerID := ctx.Args().Get(0)
	if len(containerID) == 0 {
		fmt.Fprintf(os.Stderr, "missing container ID\n")
		cli.ShowCommandHelpAndExit(ctx, "state", 1)
	}
	fifoPath := filepath.Join(LXC_PATH, containerID, SYNC_FIFO)
	log.Infof("opening fifo '%s'", fifoPath)
	f, err := os.OpenFile(fifoPath, os.O_RDONLY, 0)
	if err != nil {
		return errors.Wrap(err, "container not started - failed to open sync fifo")
	}
	defer f.Close()

	done := make(chan error)

	go func() {
		data := make([]byte, len(SYNC_FIFO_CONTENT))
		n, err := f.Read(data)
		if err != nil {
			done <- errors.Wrapf(err, "problem reading from fifo")
		}
		if n != len(SYNC_FIFO_CONTENT) || string(data) != SYNC_FIFO_CONTENT {
			done <- errors.Errorf("bad fifo content: %s", string(data))
		}
		done <- nil
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(ctx.Duration("syncfifo-timeout")):
		return fmt.Errorf("timeout reading from syncfifo %s:", fifoPath)
	}
}
