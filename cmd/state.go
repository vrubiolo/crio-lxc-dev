package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli"

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

	// environment variables for the LXC init process to
	// distinguish between created and running state
	envState        = "CRIO_LXC_STATE"
	envStateCreated = envState + "=" + stateCreated
	envStateRunning = envState + "=" + stateRunning
)

func doState(ctx *cli.Context) error {
	containerID := ctx.Args().Get(0)
	if len(containerID) == 0 {
		fmt.Fprintf(os.Stderr, "missing container ID\n")
		cli.ShowCommandHelpAndExit(ctx, "state", 1)
	}

	exists, err := containerExists(containerID)
	if err != nil {
		return errors.Wrap(err, "failed to check if container exists")
	}
	if !exists {
		return fmt.Errorf("container '%s' not found", containerID)
	}

	c, err := lxc.NewContainer(containerID, LXC_PATH)
	if err != nil {
		return errors.Wrapf(err, "failed to load container %s", containerID)
	}
	defer c.Release()

	if err := configureLogging(ctx, c); err != nil {
		return errors.Wrap(err, "failed to configure logging")
	}

	// bundlePath is the enclosing directory of the rootfs:
	// https://github.com/opencontainers/runtime-spec/blob/v1.0.0-rc4/bundle.md
	bundlePath := filepath.Dir(c.ConfigItem("lxc.rootfs.path")[0])
	annotations := map[string]string{}
	s := specs.State{
		Version:     CURRENT_OCI_VERSION,
		ID:          containerID,
		Pid:         -1,
		Bundle:      bundlePath,
		Annotations: annotations,
	}

	switch c.State() {
	case lxc.STARTING:
		s.Status = stateCreating
	case lxc.RUNNING, lxc.FROZEN, lxc.THAWED, lxc.STOPPING, lxc.ABORTING, lxc.FREEZING:
		s.Pid, s.Status = getContainerInitState(c)
	case lxc.STOPPED:
		s.Status = stateStopped
	}

	stateJson, err := json.Marshal(s)
	if err != nil {
		return errors.Wrap(err, "failed to marshal json")
	}
	fmt.Fprint(os.Stdout, string(stateJson))
	return nil
}

func getContainerInitState(c *lxc.Container) (int, string) {
	pid, proc, err := safeGetInitPid(c)
	if err != nil {
		return -1, stateStopped
	}
	if proc != nil {
		defer proc.Close()
	}

	// will fail if procfs is not mounted
	envFile := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := ioutil.ReadFile(envFile)
	if err != nil {
		log.Debugf("failed to read %s: %s", envFile, err)
		return -1, stateStopped
	}

	environ := strings.Split(string(data), "\000")
	for _, env := range environ {
		if env == envStateCreated {
			return pid, stateCreated
		}
		if env == envStateRunning {
			return pid, stateRunning
		}
	}
	return pid, stateStopped
}
