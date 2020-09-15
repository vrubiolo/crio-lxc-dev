package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	//	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	//lxc "gopkg.in/lxc/go-lxc.v2"
  "time"
)

var startCmd = cli.Command{
	Name:   "start",
	Usage:  "starts a container",
	Action: doStart,
	ArgsUsage: `[containerID]

starts <containerID>
`,
}

func doStart(ctx *cli.Context) error {
	containerID := ctx.Args().Get(0)
	if len(containerID) == 0 {
		fmt.Fprintf(os.Stderr, "missing container ID\n")
		cli.ShowCommandHelpAndExit(ctx, "state", 1)
	}

	/*
		log.Infof("about to create container")
		c, err := lxc.NewContainer(containerID, LXC_PATH)
		if err != nil {
			return errors.Wrap(err, "failed to load container")
		}
		defer c.Release()
		log.Infof("checking if running")
		if !c.Running() {
			return fmt.Errorf("'%s' is not ready", containerID)
		}
		log.Infof("not running, can start")
	*/

	fifoPath := filepath.Join(LXC_PATH, containerID, SYNC_FIFO)
	log.Infof("opening fifo '%s'", fifoPath)
	f, err := os.OpenFile(fifoPath, os.O_RDWR, 0)
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
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout reading from syncfifo %s:", fifoPath)
	}
}
