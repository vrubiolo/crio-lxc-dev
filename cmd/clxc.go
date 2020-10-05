package main

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/lxc/go-lxc.v2"
)

var log *clxc.Logger

type CrioLXC struct {
	*lxc.Container
	clxc.Logger

	Command string

	RuntimeRoot   string
	ContainerID   string
	BackupDir     string
	Backup        bool
	BackupOnError bool
	SystemdCgroup bool
	StartCommand  string
	InitCommand   string
	BundlePath    string
	SpecPath      string
}

func (c CrioLXC) VersionString() string {
	return fmt.Sprintf("%s (%s) (lxc:%s)", version, runtime.Version(), lxc.Version())
}

var ErrExist = errors.New("container already exists")
var ErrContainerNotExist = errors.New("container does not exist")

// RuntimePath builds an absolute filepath which is relative to the containers runtime root.
func (c *CrioLXC) RuntimePath(subPath ...string) string {
	return filepath.Join(c.RuntimeRoot, c.ContainerID, filepath.Join(subPath...))
}

/*
// todo create methods to create files in RuntimePath that is bind mounted into the container
func(c *CrioLXC) Share(runtimePath, containerPath string) {
}

func(c *CrioLXC) SharedPath(subPath ...string) string {
}

func(c *CrioLXC) RootfsPath(subPath ...string) string {

}
*/

func (c *CrioLXC) LoadContainer() error {
	// check for container existence by looking for config file.
	// otherwise NewContainer will return an empty container
	// struct and we'll report wrong info
	configExists, err := pathExists(c.RuntimePath("config"))
	if err != nil {
		return errors.Wrap(err, "failed to check path existence of config")
	}

	if !configExists {
		return ErrContainerNotExist
	}

	container, err := lxc.NewContainer(c.ContainerID, c.RuntimeRoot)
	if err != nil {
		return errors.Wrap(err, "failed to load container")
	}
	c.Container = container
	return nil
}

func (c *CrioLXC) CreateContainer() error {
	configExists, err := pathExists(c.RuntimePath("config"))
	if err != nil {
		return errors.Wrap(err, "failed to check path existence of config")
	}
	if configExists {
		return ErrExist
	}
	container, err := lxc.NewContainer(c.ContainerID, c.RuntimeRoot)
	if err != nil {
		return err
	}
	c.Container = container
	if err := os.MkdirAll(c.RuntimePath(), 0770); err != nil {
		return errors.Wrap(err, "failed to create container dir")
	}
	return nil
}

// Release releases/closes allocated resources (lxc.Container, LogFile)
func (c CrioLXC) Release() {
	if c.Container != nil {
		c.Container.Release()
	}
	if c.LogFile != nil {
		c.LogFile.Close()
	}
}

func (c *CrioLXC) SetConfigItem(key, value string) error {
	err := c.Container.SetConfigItem(key, value)
	if err != nil {
		log.Error().Err(err).Str("key:", key).Str("value:", value).Msg("lxc config")
	} else {
		log.Debug().Str("key:", key).Str("value:", value).Msg("lxc config")
	}
	return errors.Wrap(err, "failed to set lxc config item '%s=%s'")
}

// BackupRuntimeDirectory creates a backup of the container runtime resources.
// It returns the path to the backup directory.
//
// The following resources are backed up:
// - all resources created by crio-lxc (lxc config, init script, device creation script ...)
// - lxc logfiles (if logging is setup per container)
// - the runtime spec
func (c *CrioLXC) BackupRuntimeResources() (backupDir string, err error) {
	backupDir = filepath.Join(c.BackupDir, c.ContainerID)
	err = os.MkdirAll(c.BackupDir, 0755)
	if err != nil {
		return "", errors.Wrap(err, "failed to create backup dir")
	}
	err = RunCommand("cp", "-r", "-p", clxc.RuntimePath(), backupDir)
	if err != nil {
		return backupDir, errors.Wrap(err, "failed to copy lxc runtime directory")
	}
	// remove syncfifo because it is not of any use and blocks 'grep' within the backup directory.
	os.Remove(filepath.Join(backupDir, SYNC_FIFO_PATH))
	err = RunCommand("cp", clxc.SpecPath, backupDir)
	if err != nil {
		return backupDir, errors.Wrap(err, "failed to copy runtime spec to backup dir")
	}
	return backupDir, nil
}
