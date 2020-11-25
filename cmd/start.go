package main

import (
	"github.com/urfave/cli/v2"
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
func ReadFifo(fifoPath string, timeout time.Duration) error {
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

	data := make([]byte, len(SyncFifoContent))
	n, err := f.Read(data)
	if err != nil {
		return errors.Wrap(err, "problem reading from fifo")
	}
	if n != len(SyncFifoContent) || string(data) != SyncFifoContent {
		return errors.Errorf("bad fifo content: %s", string(data))
	}
	return nil
}
