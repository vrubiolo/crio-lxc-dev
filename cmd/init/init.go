package main

import (
	"os"
	"os/user"
	"os/exec"
	"strings"

	//caps "kernel.org/pub/linux/libs/security/libcap/cap"
	"github.com/lxc/crio-lxc/clxc"
	"golang.org/x/sys/unix"
)

func fail(err error, step string) {
	panic("init step [" + step + "] failed: " + err.Error())
}

func main() {
	spec, err := clxc.ReadSpec(clxc.INIT_SPEC)
	if err != nil {
		panic(err)
	}

	fifo, err := os.OpenFile(clxc.SYNC_FIFO_PATH, os.O_WRONLY, 0)
	if err != nil {
		fail(err, "open sync fifo")
	}

	_, err = fifo.Write([]byte(clxc.SYNC_FIFO_CONTENT))
	if err != nil {
		fail(err, "write to sync fifo")
	}

  /*
  c := caps.GetProc()
  capSetgid, err :=  c.GetFlag(caps.SETGID, caps.Effective)
  if err != nil {
    fail(err, "caps get setgid")
  }
  */
	if capSetgid && len(spec.Process.User.AdditionalGids) > 0 {
		  gids := make([]int, len(spec.Process.User.AdditionalGids))
		  for _, gid := range spec.Process.User.AdditionalGids {
			  gids = append(gids, int(gid))
		  }

		  err := caps.SetGroups(int(spec.Process.User.UID), gids)
		  if err != nil {
			  fail(err, "setgroups")
		  }
	  }
	}

  capSetuid, err :=  c.GetFlag(caps.SETUID, caps.Effective)
  if err != nil {
    fail(err, "caps get setuid")
  }
	err := caps.SetUID(int(spec.Process.User.UID))
	if err != nil {
		fail(err, "setuid")
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
	  u, err := user.Lookup(userName)
	  if err == nil && u.HomeDir != "" {
	    return append(env, "HOME="+u.HomeDir)
			}
	}
	// and as last resort the provided fallback path is used
	return append(env, "HOME="+fallback)
}
