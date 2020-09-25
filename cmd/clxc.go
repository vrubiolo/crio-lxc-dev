package main

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
	"path/filepath"
	"runtime"

  "github.com/rs/zerolog"
	"gopkg.in/lxc/go-lxc.v2"
)

var log zerolog.Logger

type CrioLXC struct {
	*lxc.Container

  Command string

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

var ErrExist = errors.New("container already exists")
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
  log = zerolog.New(f).With().Str("cmd:", c.Command).Str("cid:",c.ContainerID).Logger()

	level, err := parseLogLevel(c.LogLevelString)
	if err != nil {
		log.Error().Err(err).Stringer("loglevel:", level).Msg("using fallback log-level")
	}
	c.LogLevel = level

	switch level {
	case lxc.TRACE:
	  zerolog.SetGlobalLevel(zerolog.TraceLevel)
  case lxc.DEBUG:
	  zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case lxc.INFO:
	  zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case lxc.WARN:
	  zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case lxc.ERROR:
	  zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	}
	return nil
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
