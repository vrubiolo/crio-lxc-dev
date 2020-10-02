package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	lxc "gopkg.in/lxc/go-lxc.v2"
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

// runtime states https://github.com/opencontainers/runtime-spec/blob/v1.0.2/runtime.md
const (
	// the container is being created (step 2 in the lifecycle)
	stateCreating = "creating"
	// the runtime has finished the create operation (after step 2 in the lifecycle),
	// and the container process has neither exited nor executed the user-specified program
	stateCreated = "created"
	// the container process has executed the user-specified program
	// but has not exited (after step 5 in the lifecycle)
	stateRunning = "running"
	// the container process has exited (step 7 in the lifecycle)
	stateStopped = "stopped"

	// environment variable to detect container runtime states
	// - stateCreated: crio-lxc-init is started but blocking at the syncfifo
	// - stateRunning: crio-lxc-init has executed container process
	envStateCreated = "CRIO_LXC_STATE=" + stateCreated
)

func doState(ctx *cli.Context) error {
	err := clxc.LoadContainer()
	if err != nil {
		return errors.Wrapf(err, "failed to load container")
	}
	c := clxc.Container

	// bundlePath is the enclosing directory of the rootfs:
	// https://github.com/opencontainers/runtime-spec/blob/v1.0.0-rc4/bundle.md
	bundlePath := filepath.Dir(c.ConfigItem("lxc.rootfs.path")[0])
	annotations := map[string]string{}
	s := specs.State{
		Version:     CURRENT_OCI_VERSION,
		ID:          c.Name(),
		Pid:         -1,
		Bundle:      bundlePath,
		Annotations: annotations,
	}

	switch state := c.State(); state {
	case lxc.STARTING:
		s.Status = stateCreating
	case lxc.STOPPED:
		s.Status = stateStopped
	default:
		s.Pid, s.Status = getContainerInitState(c)
	}

	stateJson, err := json.Marshal(s)
	if err != nil {
		return errors.Wrap(err, "failed to marshal json")
	}
	fmt.Fprint(os.Stdout, string(stateJson))
	return nil
}

// getContainerInitState returns the runtime state of the container.
// It is used to determine whether the container state is 'created' or 'running'.
// The init process environment contains #envStateCreated if the the container
// is created, but not yet running/started.
// This requires the proc filesystem to be mounted on the host.
func getContainerInitState(c *lxc.Container) (int, string) {
	pid, proc, err := safeGetInitPid(c)
	if err != nil {
		return -1, stateStopped
	}
	if proc != nil {
		defer proc.Close()
	}

	envFile := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := ioutil.ReadFile(envFile)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "failed to read init process environment %s: %s", envFile, err)
		return -1, stateStopped
	}

	environ := strings.Split(string(data), "\000")
	for _, env := range environ {
		if env == envStateCreated {
			return pid, stateCreated
		}
	}
	// the init process is runnig
	// checking for the existence of #envStateRunning within the environment
	// will not work for processes which call exec with a modified environment e.g the nginx image.
	return pid, stateRunning
}
