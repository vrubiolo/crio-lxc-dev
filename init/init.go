package main

import (
	"github.com/lxc/crio-lxc/clxc"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strings"
)

type initError struct {
	err  error
	step string
}

func (e initError) Error() string {
	return "failed to:" + e.step + ":" + e.Error()
}

func fail(err error, step string) {
	// TODO write termination message ?
	// create a custom error ?
	panic(initError{err, step})
}

func main() {
	// write to syncfifo
	var spec clxc.InitSpec
	err := spec.ParseFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	fifo, err := os.OpenFile(spec.SyncFifo, os.O_WRONLY, 0)
	if err != nil {
		fail(err, "open sync fifo")
	}

	_, err = fifo.Write([]byte(spec.Message))
	if err != nil {
		fail(err, "write message to sync fifo")
	}

	if len(spec.AdditionalGids) > 0 {
		err := unix.Setgroups(spec.AdditionalGids)
		if err != nil {
			fail(err, "setgroups")
		}
	}

	//	env := unix.Environ()
	//env = append(env, spec.Env...)
	env := spec.Env
	env = setHome(env, spec.UserName, spec.Cwd)

	if err := unix.Chdir(spec.Cwd); err != nil {
		fail(err, "change to cwd")
	}

	//	runtime.LockOSThread()
	cmdPath, err := exec.LookPath(spec.Args[0])
	if err != nil {
		fail(err, "lookup cmd path")
	}

	err = unix.Exec(cmdPath, spec.Args, env)
	if err != nil {
		fail(err, "exec")
	}
}

func setHome(env []string, userName string, fallback string) []string {
	// either use existing HOME environment variable
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOME=") {
			return env
		}
		return env
	}
	// or lookup passwd for home directory
	if userName != "" {
		passwd := "/etc/passwd"
		if _, err := os.Stat(passwd); err == nil {
			if u := GetUser(passwd, userName); u != nil && u.Home != "" {
				return append(env, "HOME="+u.Home)
			}
		}
	}
	// and use fallback as last resort
	return append(env, "HOME="+fallback)
}
