package main

import (
	"fmt"
	"github.com/apex/log"
	"github.com/pkg/errors"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/lxc/go-lxc.v2"
)

type CrioLXC struct {
	*lxc.Container

	RuntimeRoot    string
	ContainerID    string
	LogFile        *os.File
	LogFilePath    string
	LogLevel       lxc.LogLevel
	LogLevelString string
	BackupDir      string
	BackupOnError  bool
	SystemdCgroup  bool
	BusyboxBinary  string
	StartCommand   string
}

func (c CrioLXC) VersionString() string {
	return fmt.Sprintf("%s (%s) (lxc:%s)", version, runtime.Version(), lxc.Version())
}

var ErrNotExist = errors.New("container does not exist")

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
		return ErrNotExist
	}

	container, err := lxc.NewContainer(c.ContainerID, c.RuntimeRoot)
	if err != nil {
		return errors.Wrap(err, "failed to load container")
	}
	c.Container = container
	return clxc.configureLogging()
}

func (c *CrioLXC) CreateContainer() error {
	container, err := lxc.NewContainer(c.ContainerID, c.RuntimeRoot)
	if err != nil {
		return err
	}
	c.Container = container
	if err := os.MkdirAll(c.RuntimePath(), 0770); err != nil {
		return errors.Wrap(err, "failed to create container dir")
	}
	return clxc.configureLogging()
}

// Release releases/closes allocated resources (lxc.Container, LogFile)
func (c CrioLXC) Release() {
	if c.Container != nil {
		c.Release()
	}
	if c.LogFile != nil {
		c.LogFile.Close()
	}
}

// By default logging is done on a container base
// log-dir /lxc-path/{container id}/{lxc.log, crio-lxc.log}
func (c *CrioLXC) configureLogging() error {
	if c.LogFilePath == "" {
		c.LogFilePath = c.RuntimePath("crio-lxc.log")
	}
	f, err := os.OpenFile(c.LogFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640)
	if err != nil {
		return errors.Wrapf(err, "failed to open log file %s", c.LogFilePath)
	}
	c.LogFile = f

	level, err := parseLogLevel(c.LogLevelString)
	if err != nil {
		log.Errorf("Using fallback log-level %q: %s", level, err)
	}
	switch level {
	case lxc.TRACE, lxc.DEBUG:
		log.SetLevel(log.DebugLevel)
	case lxc.INFO:
		log.SetLevel(log.InfoLevel)
	case lxc.WARN:
		log.SetLevel(log.WarnLevel)
	case lxc.ERROR:
		log.SetLevel(log.ErrorLevel)
	}
	return nil
}
