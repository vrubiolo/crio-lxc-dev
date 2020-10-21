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

	// bundlePath is the enclosing directory of the rootfs:
	// https://github.com/opencontainers/runtime-spec/blob/v1.0.0-rc4/bundle.md
	bundlePath := filepath.Dir(clxc.GetConfigItem("lxc.rootfs.path"))

	s := specs.State{
		Version:     CURRENT_OCI_VERSION,
		ID:          clxc.Name(),
		Bundle:      bundlePath,
		Annotations: map[string]string{},
	}

  s.Pid, s.Status, err = clxc.getContainerState()

	if stateJson, err := json.Marshal(s); err == nil {
	  fmt.Fprint(os.Stdout, string(stateJson))
	} else {
		return errors.Wrap(err, "failed to marshal json")
	}
	return err
}

