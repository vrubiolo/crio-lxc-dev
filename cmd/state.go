package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

var stateCmd = cli.Command{
	Name:   "state",
	Usage:  "returns state of a container",
	Action: doState,
	ArgsUsage: `[containerID]

<containerID> is the ID of the container you want to know about.
`,
	Flags: []cli.Flag{},
}

func doState(ctx *cli.Context) error {
	err := clxc.LoadContainer()
	if err != nil {
		return errors.Wrapf(err, "failed to load container")
	}

	// TODO save BundlePath to init spec
	bundlePath := filepath.Join("/var/run/containers/storage/overlay-containers/", clxc.Name(), "userdata")

	s := specs.State{
		Version: CURRENT_OCI_VERSION,
		ID:      clxc.Name(),
		Bundle:  bundlePath,
	}

	s.Pid, s.Status, err = clxc.getContainerState()
	log.Debug().Int("pid:", s.Pid).Str("state:", s.Status).Msg("container state")

	if stateJson, err := json.Marshal(s); err == nil {
		fmt.Fprint(os.Stdout, string(stateJson))
		log.Trace().RawJSON("state:", stateJson).Msg("container state")
	} else {
		return errors.Wrap(err, "failed to marshal json")
	}
	return err
}
