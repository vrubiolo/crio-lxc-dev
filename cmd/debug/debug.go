package main

import (
  "fmt"
  "os"
  "io"
  "os/exec"
  "github.com/segmentio/ksuid"
  "bufio"
  "github.com/pkg/errors"
)

var bin = "/usr/bin/runc"

func main() {
  f, err := os.OpenFile("/tmp/runc.log", os.O_WRONLY | os.O_CREATE | os.O_APPEND, 0640)
  if err != nil {
    panic(err)
  }
  defer f.Close()

  outRdr, outWr := io.Pipe()
  errRdr, errWr := io.Pipe()

  outTee := io.TeeReader(outRdr, os.Stdout)
  errTee := io.TeeReader(errRdr, os.Stderr)

  done := make(chan error)

  uid := ksuid.New().String()

  go func() {
    br := bufio.NewScanner(outTee)
    for br.Scan() {
      fmt.Fprintf(f, "%s out %s\n", uid, br.Text())
    }
    done <- errors.Wrap(br.Err(), "failed to read from stdout")
  }()

  go func() {
    br := bufio.NewScanner(errTee)
    for br.Scan() {
      fmt.Fprintf(f, "%s err %s\n", uid, br.Text())
    }
    done <- errors.Wrap(br.Err(), "failed to read from sterr")
  }()

  fmt.Fprintf(f, "%s cmd: %s\n", uid, os.Args)

  cmd := exec.Command(bin, os.Args[1:]...)
  //cmd := exec.Command("/usr/bin/runc", os.Args[1:]...)
  cmd.Stdout = outWr
  cmd.Stderr = errWr
  errRun = cmd.Run()
  outWr.Close()
  errWr.Close()

  err = <-done
  if err != nil && err != io.EOF {
    panic(err)
  }
  err = <-done
  if err != nil && err != io.EOF {
    panic(err)
  }

  statusCode := cmd.ProcessState.ExitCode()
  fmt.Fprintf(f, "%s exit %d (err:%s)\n", uid, statusCode, errRun)
  os.Exit(statusCode)
}
