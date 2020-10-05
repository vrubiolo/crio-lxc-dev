package main

import (
	"github.com/lxc/crio-lxc/clxc"
	"golang.org/x/sys/unix"
	"io/ioutil"
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
	e := initError{err, step}
	ioutil.WriteFile("/dev/termination-log", []byte(e.Error()), 0640)
	panic(e)
}

func main() {
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

	if clxc.HasCapability(spec.Spec, "CAP_SETGID") && len(spec.Process.User.AdditionalGids) > 0 {
		gids := make([]int, len(spec.Process.User.AdditionalGids))
		for _, gid := range spec.Process.User.AdditionalGids {
			gids = append(gids, int(gid))
		}
		err := unix.Setgroups(gids)
		if err != nil {
			fail(err, "setgroups")
		}
	}

	err = clxc.CreateDevices(spec.Spec)
	if err != nil {
		fail(err, "create devices")
	}

	env := setHome(spec.Process.Env, spec.Process.User.Username, spec.Process.Cwd)

	if err := unix.Chdir(spec.Process.Cwd); err != nil {
		fail(err, "change to cwd")
	}

	cmdPath, err := exec.LookPath(spec.Process.Args[0])
	if err != nil {
		fail(err, "lookup cmd path")
	}

	err = unix.Exec(cmdPath, spec.Process.Args, env)
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
	// or lookup users home directory in passwd
	if userName != "" {
		passwd := "/etc/passwd"
		if _, err := os.Stat(passwd); err == nil {
			if u := GetUser(passwd, userName); u != nil && u.Home != "" {
				return append(env, "HOME="+u.Home)
			}
		}
	}
	// and as last resort the provided fallback path is used
	return append(env, "HOME="+fallback)
}
