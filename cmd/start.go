package main

import (
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"path/filepath"
	"time"

	"github.com/lxc/crio-lxc/cmd/internal"
	"github.com/urfave/cli/v2"
)

var startCmd = cli.Command{
	Name:   "start",
	Usage:  "starts a container",
	Action: doStart,
	ArgsUsage: `[containerID]

starts <containerID>
`,
	Flags: []cli.Flag{
		&cli.DurationFlag{
			Name:        "timeout",
			Usage:       "timeout for reading from syncfifo",
			EnvVars:     []string{"CRIO_LXC_START_TIMEOUT"},
			Value:       time.Second * 60,
			Destination: &clxc.StartTimeout,
		},
	},
}

func doStart(ctx *cli.Context) error {
	log.Info().Msg("notify init to start container process")

	err := clxc.loadContainer()
	if err != nil {
		return err
	}

	return readFifo(clxc.runtimePath(internal.SyncFifoPath), clxc.StartTimeout)
}

// ReadFifo reads the content from the SyncFifo that was written by #WriteFifo.
// The read operation is aborted after the given timeout.
func readFifo(fifoPath string, timeout time.Duration) error {
	// #nosec
	f, err := os.OpenFile(fifoPath, os.O_RDONLY, 0)
	if err != nil {
		return errors.Wrap(err, "failed to open sync fifo")
	}
	err = f.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return errors.Wrap(err, "failed to set deadline")
	}
	// #nosec
	defer f.Close()

	var pid int64
	err = binary.Read(f, binary.LittleEndian, &pid)
	if err != nil {
		return errors.Wrap(err, "problem reading from fifo")
	}
	return createPidFile(clxc.PidFile, pid)
}

// createPidFile atomically creates a pid file for the given pid at the given path
func createPidFile(path string, pid int64) error {
	tmpDir := filepath.Dir(path)
	tmpName := filepath.Join(tmpDir, fmt.Sprintf(".%s", filepath.Base(path)))

	// #nosec
	f, err := os.OpenFile(tmpName, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%d", pid)
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
