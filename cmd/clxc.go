package main

import (
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	api "github.com/lxc/crio-lxc/clxc"
	"github.com/rs/zerolog"
	"gopkg.in/lxc/go-lxc.v2"
)

var log zerolog.Logger

// time format used for logger
const TimeFormatLXCMillis = "20060102150405.000"

type CrioLXC struct {
	*lxc.Container

	Command string

	// [ global settings ]
	RuntimeRoot    string
	ContainerID    string
	LogFile        *os.File
	LogFilePath    string
	LogLevel       lxc.LogLevel
	LogLevelString string
	BackupDir      string
	Backup         bool
	BackupOnError  bool
	SystemdCgroup  bool
	MonitorCgroup  string
	StartCommand   string
	InitCommand    string
	HookCommand    string

	// feature gates
	Seccomp       bool
	Capabilities  bool
	Apparmor      bool
	CgroupDevices bool

	// create flags
	BundlePath    string
	SpecPath      string // BundlePath + "/config.json"
	PidFile       string
	ConsoleSocket string
	CreateTimeout time.Duration

	// start flags
	StartTimeout time.Duration
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

	// crio-lxc-init is started but blocking at the syncfifo
	envStateCreated = "CRIO_LXC_STATE=" + stateCreated
)

func (c CrioLXC) VersionString() string {
	return fmt.Sprintf("%s (%s) (lxc:%s)", version, runtime.Version(), lxc.Version())
}

var ErrExist = errors.New("container already exists")
var ErrContainerNotExist = errors.New("container does not exist")

// RuntimePath builds an absolute filepath which is relative to the container runtime root.
func (c *CrioLXC) RuntimePath(subPath ...string) string {
	return filepath.Join(c.RuntimeRoot, c.ContainerID, filepath.Join(subPath...))
}

func (c *CrioLXC) LoadContainer() error {
	// Check for container existence by looking for config file.
	// Otherwise lxc.NewContainer will return an empty container
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
	if err := container.LoadConfigFile(c.RuntimePath("config")); err != nil {
		return err
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

func (c *CrioLXC) configureLogging() error {
	logDir := filepath.Dir(c.LogFilePath)
	err := os.MkdirAll(logDir, 0750)
	if err != nil {
		return errors.Wrapf(err, "failed to create log file directory %s", logDir)
	}

	f, err := os.OpenFile(c.LogFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640)
	if err != nil {
		return errors.Wrapf(err, "failed to open log file %s", c.LogFilePath)
	}
	c.LogFile = f

	zerolog.TimestampFieldName = "t"
	zerolog.LevelFieldName = "p"
	zerolog.MessageFieldName = "m"
	zerolog.TimeFieldFormat = TimeFormatLXCMillis

	// NOTE It's not possible change the possition of the timestamp.
	// The ttimestamp is appended to the to the log output because it is dynamically rendered
	// see https://github.com/rs/zerolog/issues/109
	log = zerolog.New(f).With().Timestamp().Str("cmd:", c.Command).Str("cid:", c.ContainerID).Logger()

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

func (c CrioLXC) CanConfigure(keys ...string) bool {
	for _, key := range keys {
		if !lxc.IsSupportedConfigItem(key) {
			log.Info().Str("key:", key).Msg("unsupported lxc config item")
			return false
		}
	}
	return true
}

func (c *CrioLXC) GetConfigItem(key string) string {
	vals := c.Container.ConfigItem(key)
	if len(vals) > 0 {
		first := vals[0]
		// some lxc config values are set to '(null)' if unset
		// eg. lxc.cgroup.dir
		if first != "(null)" {
			return first
		}
	}
	return ""
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

// BackupRuntimeResources creates a backup of the container runtime resources.
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
	os.Remove(filepath.Join(backupDir, api.SYNC_FIFO_PATH))
	err = RunCommand("cp", clxc.SpecPath, backupDir)
	if err != nil {
		return backupDir, errors.Wrap(err, "failed to copy runtime spec to backup dir")
	}
	return backupDir, nil
}

func parseLogLevel(s string) (lxc.LogLevel, error) {
	switch strings.ToLower(s) {
	case "trace":
		return lxc.TRACE, nil
	case "debug":
		return lxc.DEBUG, nil
	case "info":
		return lxc.INFO, nil
	case "warn":
		return lxc.WARN, nil
	case "error":
		return lxc.ERROR, nil
	default:
		return lxc.ERROR, fmt.Errorf("Invalid log-level %s", s)
	}
}

func (clxc *CrioLXC) getContainerState() (int, string, error) {
	switch state := clxc.State(); state {
	case lxc.STARTING:
		return -1, stateCreating, nil
	case lxc.STOPPED:
		return -1, stateStopped, nil
	default:
		return clxc.getContainerInitState()
	}
}

// getContainerInitState returns the runtime state of the container.
// It is used to determine whether the container state is 'created' or 'running'.
// The init process environment contains #envStateCreated if the the container
// is created, but not yet running/started.
// This requires the proc filesystem to be mounted on the host.
func (clxc *CrioLXC) getContainerInitState() (int, string, error) {
	pid, proc, err := clxc.safeGetInitPid()
	if err != nil {
		// Errors returned from safeGetInitPid are non-fatal and indicate either
		// that the init process has died. // TODO log error in debug or trace mode
		return -1, stateStopped, nil
	}
	if proc != nil {
		defer proc.Close()
	}

	envFile := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := ioutil.ReadFile(envFile)
	if err != nil {
		// This is fatal. It should not happen because we a filehandle to /proc/%d is open.
		return -1, stateStopped, errors.Wrapf(err, "failed to read init process environment %s", envFile)
	}

	environ := strings.Split(string(data), "\000")
	for _, env := range environ {
		if env == envStateCreated {
			return pid, stateCreated, nil
		}
	}
	return pid, stateRunning, nil
}

// This is not required when lxc uses pidfd internally
func (c *CrioLXC) safeGetInitPid() (pid int, proc *os.File, err error) {
	pid = c.InitPid()
	if pid < 0 {
		return -1, nil, fmt.Errorf("expected init pid > 0, but was %d", pid)
	}
	// Open the proc directory of the init process to avoid that
	// it's PID is recycled before it receives the signal.
	proc, err = os.Open(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		// This may fail if either the proc filesystem is not mounted, or
		// the process has died
		fmt.Fprintf(os.Stderr, "failed to open /proc/%d : %s", pid, err)
	}
	// double check that the init process still exists, and the proc
	// directory actually belongs to the init process.
	pid2 := c.InitPid()
	if pid2 != pid {
		proc.Close()
		return -1, nil, errors.Wrapf(err, "init process %d has already died", pid)
	}
	return pid, proc, nil
}

func (clxc *CrioLXC) waitContainerCreated(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		log.Trace().Msg("poll for container init state")
		pid, state, err := clxc.getContainerInitState()
		if err != nil {
			return errors.Wrap(err, "failed to wait for container container creation")
		}

		if pid > 0 && state == stateCreated {
			return nil
		}
		time.Sleep(time.Millisecond * 50)
	}
	return fmt.Errorf("timeout (%s) waiting for container creation", timeout)
}
