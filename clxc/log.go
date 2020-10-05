import (
	"github.com/rs/zerolog"
)

type Logger struct {
  zerolog.Logger

	LogFilePath    string
	LogLevelString string

	LogFile        *os.File
	LogLevel       zerolog.LogLevel
}

// By default logging is done on a container base
// log-dir /lxc-path/{container id}/{lxc.log, crio-lxc.log}
func (log *Logger) Create() error {
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
	log = zerolog.New(f).With().Str("cmd:", c.Command).Str("cid:", c.ContainerID).Logger()

	level, err := zerolog.ParseLevel(c.LogLevelString)
	if err != nil {
		log.Error().Err(err).Stringer("loglevel:", level).Msg("using fallback log-level")
	}
	c.LogLevel = level
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	return nil
}

// 0 = trace, 1 = debug, 2 = info, 3 =  no‐tice, 4 = warn, 5 = error, 6 = critical, 7 = alert, and 8 = fatal.
const (
  LxcTrace = 0
  LxcDebug = iota
  LxcInfo 
  LxcNotice
  LxcWarn
  LxcError
  LxcCritical
  LxcAlert
  LxcFatal
}

// 
func lxcLogLevel(zerolog.LogLevel) lxc.LogLevel {
  switch level {
    case zerolog.TraceLevel: return lxc.TRACE
    case zerolog.DebugLevel: return lxc.DEBUG
    case zerolog.InfoLevel: return lxc.INFO
    case zerolog.WarnLevel: return lxc.WARN
    case zerolog.ErrorLevel: return lxc.ERROR
    case zerolog.TraceLevel: return lxc.TRACE
  }
}

// zerolog
const (
    // DebugLevel defines debug log level.
    DebugLevel Level = iota
    // InfoLevel defines info log level.
    InfoLevel
    // WarnLevel defines warn log level.
    WarnLevel
    // ErrorLevel defines error log level.
    ErrorLevel
    // FatalLevel defines fatal log level.
    FatalLevel
    // PanicLevel defines panic log level.
    PanicLevel
    // NoLevel defines an absent log level.
    NoLevel
    // Disabled disables the logger.
    Disabled

    // TraceLevel defines trace log level.
    TraceLevel Level = -1
)
