// Allow Setns to be called safely
// https://github.com/vishvananda/netns/issues/17
// +build go1.10

package main

import (
	"fmt"
	"os"
	"time"
	"errors"
	"flag"

	lxc "gopkg.in/lxc/go-lxc.v2"
)

func hold(lxcpath string, containerID string, timeout time.Duration) error {
	if len(containerID) == 0 {
		return errors.New("missing container ID")
	}
	c, err := lxc.NewContainer(containerID, lxcpath)
	if err != nil {
		return fmt.Errorf("failed to load container: %s", err)
	}
	defer c.Release()

	if !c.Running() {
		return fmt.Errorf("container '%s' is not running", containerID)
	}

	pidfd, err := c.InitPidFd()
	if err != nil {
		return err
	}
	defer pidfd.Close()

	pid := c.InitPid()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "init PID is %d - sleeping for %s", pid, timeout)
	time.Sleep(timeout)
	_, err = os.Stat(fmt.Sprintf("/proc/%d/", pid))
	return err
}

func main() {
	var lxcpath string
	var containerID string
	var timeout time.Duration
	flag.StringVar(&lxcpath, "lxc-path", "/run/crio-lxc", "LXC_PATH")
	flag.StringVar(&containerID, "id", "", "container ID")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "timeout")
	flag.Parse()

	err :=	hold(lxcpath, containerID, timeout)
	if err != nil {
		panic(err)
	}

}
// https://github.com/vishvananda/netns/issues/17
// It's
/*
	cmd := exec.Command("crio-lxc-kill", LXC_PATH, containerID, strconv.Itoa(int(signum)))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
*/
