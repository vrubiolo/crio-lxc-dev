package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	lxc "gopkg.in/lxc/go-lxc.v2"
)

var deleteCmd = cli.Command{
	Name:   "delete",
	Usage:  "deletes a container",
	Action: doDelete,
	ArgsUsage: `[containerID]

<containerID> is the ID of the container to delete
`,
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "force",
			Usage: "force deletion",
		},
	},
}

func doDelete(ctx *cli.Context) error {
	err := clxc.LoadContainer()
	if err != nil {
		return err
	}
	c := clxc.Container

	hasErrors := c.ErrorNum() != 0
	state := c.State()
	if state != lxc.STOPPED {
		if !ctx.Bool("force") {
			return fmt.Errorf("container must be stopped before delete (current state is %s)", state)
		}

		if err := c.Stop(); err != nil {
			return errors.Wrap(err, "failed to stop container")
		}
	}
	if err := c.Destroy(); err != nil {
		return errors.Wrap(err, "failed to delete container.")
	}

	if hasErrors && clxc.BackupOnError {
		return os.Rename(clxc.RuntimePath(), filepath.Join(clxc.BackupDir, clxc.ContainerID))
	}
	// "Note that resources associated with the container,
	// but not created by this container, MUST NOT be deleted."

	// TODO - because we set rootfs.managed=0, Destroy() doesn't
	// delete the /var/lib/lxc/$containerID/config file:
	return os.RemoveAll(clxc.RuntimePath())
}
