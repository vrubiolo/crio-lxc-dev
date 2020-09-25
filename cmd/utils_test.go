package main

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveMountDestinationAbsolute(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "golang.test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	err = os.MkdirAll(filepath.Join(tmpdir, "folder1"), 0750)
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Join(tmpdir, "folder2"), 0750)
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Join(tmpdir, "folder3"), 0750)
	require.NoError(t, err)
	err = os.Symlink("/folder2", filepath.Join(tmpdir, "folder1", "f2"))
	require.NoError(t, err)
	err = os.Symlink("/folder3", filepath.Join(tmpdir, "folder2", "f3"))
	require.NoError(t, err)
	err = ioutil.WriteFile(filepath.Join(tmpdir, "folder3", "test.txt"), []byte("hello"), 0640)
	require.NoError(t, err)

	p, err := resolveMountDestination(tmpdir, "/folder1/f2/f3/test.txt")
	require.Equal(t, filepath.Join(tmpdir, "/folder3/test.txt"), p)
	require.NoError(t, err)

	p, err = resolveMountDestination(tmpdir, "/folder1/f2/xxxxx/fooo")
	require.Equal(t, filepath.Join(tmpdir, "/folder2/xxxxx/fooo"), p)
	require.Error(t, err, os.ErrExist)

	p, err = resolveMountDestination(tmpdir, "/folder1/f2/f3/hello.txt")
	require.Equal(t, filepath.Join(tmpdir, "/folder3/hello.txt"), p)
	require.Error(t, err, os.ErrExist)
}

func TestResolveMountDestinationRelative(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "golang.test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	err = os.MkdirAll(filepath.Join(tmpdir, "folder1"), 0750)
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Join(tmpdir, "folder2"), 0750)
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Join(tmpdir, "folder3"), 0750)
	require.NoError(t, err)
	err = os.Symlink("../folder2", filepath.Join(tmpdir, "folder1", "f2"))
	require.NoError(t, err)
	err = os.Symlink("../folder3", filepath.Join(tmpdir, "folder2", "f3"))
	require.NoError(t, err)
	err = ioutil.WriteFile(filepath.Join(tmpdir, "folder3", "test.txt"), []byte("hello"), 0640)
	require.NoError(t, err)

	//err = os.Symlink("../../folder2", filepath.Join(tmpdir, "folder1", "f2"))
	//require.NoError(t, err)

	p, err := resolveMountDestination(tmpdir, "/folder1/f2/f3/test.txt")
	require.Equal(t, filepath.Join(tmpdir, "/folder3/test.txt"), p)
	require.NoError(t, err)

	p, err = resolveMountDestination(tmpdir, "/folder1/f2/xxxxx/fooo")
	require.Equal(t, filepath.Join(tmpdir, "/folder2/xxxxx/fooo"), p)
	require.Error(t, err, os.ErrExist)

	p, err = resolveMountDestination(tmpdir, "/folder1/f2/f3/hello.txt")
	require.Equal(t, filepath.Join(tmpdir, "/folder3/hello.txt"), p)
	require.Error(t, err, os.ErrExist)
}

func TestEmitCommandFile(t *testing.T) {
	t.Skip("must be fixed")
	cmd := exec.Command("/bin/sh", "-c", "echo foo\n echo bar\n")
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
	specFile := "/tmp/crio-lxc.log.582641.config.json"

	spec, err := readBundleSpec(specFile)
	if err != nil {
		panic(err)
	}

	buf := strings.Builder{}
	buf.WriteString("exec")
	for _, arg := range spec.Process.Args {
		buf.WriteRune(' ')
		buf.WriteRune('"')
		//fmt.Fprintf(&buf, "%s", arg)
		buf.WriteString(arg)
		buf.WriteRune('"')
	}
	fmt.Println(buf.String())
}

func TestIsStaticBinary(t *testing.T) {
	require.NoError(t, isStaticBinary("/bin/zcat"))
	require.Error(t, isStaticBinary("/usr/bin/systemd"))
}

func TestCapabilities(t *testing.T) {
	require.NoError(t, runtimeHasCapabilitySupport("/usr/local/bin/crio-lxc-start"))
	require.Error(t, runtimeHasCapabilitySupport("/bin/zcat"))
}

func TestKernelRelease(t *testing.T) {
	release := "5.8.0-trunk-amd64"
	r, err := ParseUtsnameRelease(release)
	require.NoError(t, err)
	require.Equal(t, "trunk-amd64", r.Suffix)
	require.True(t, r.GreaterEqual(5, 8, 0))
	require.True(t, r.GreaterEqual(4, 9, 0))
	require.False(t, r.GreaterEqual(5, 8, 1))

	release = "5.9.3"
	r, err = ParseUtsnameRelease(release)
	require.NoError(t, err)
	require.Empty(t, r.Suffix)
}

func TestGetUser(t *testing.T) {
	passwd := `root:x:0:0:root:/root:/bin/bash
_apt:x:100:65534:xxx:/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin`

	f, err := ioutil.TempFile("", "passwd")
	require.NoError(t, err)
	_, err = fmt.Fprintln(f, passwd)
	require.NoError(t, err)
	f.Close()

	u := GetUser(f.Name(), "systemd-coredump")
	require.NotNil(t, u)
	require.Equal(t, "/", u.Home)

	u = GetUser(f.Name(), "_apt")
	require.NotNil(t, u)
	require.Equal(t, "/nonexistent", u.Home)

	u = GetUser(f.Name(), "root")
	require.NotNil(t, u)
	require.Equal(t, "/root", u.Home)
}

func TestAccessMask(t *testing.T) {
	// setuid 4, setgid 2, sticky 1
	require.Equal(t, "01707", accessMask(0707|os.ModeSticky))
	require.Equal(t, "01777", accessMask(os.ModePerm|os.ModeSticky))
	require.Equal(t, "02777", accessMask(os.ModePerm|os.ModeSetgid))
	require.Equal(t, "04777", accessMask(os.ModePerm|os.ModeSetuid))

	require.Equal(t, "03777", accessMask(os.ModePerm|os.ModeSticky|os.ModeSetgid))
	require.Equal(t, "05777", accessMask(os.ModePerm|os.ModeSticky|os.ModeSetuid))
	require.Equal(t, "06777", accessMask(os.ModePerm|os.ModeSetgid|os.ModeSetuid))
	require.Equal(t, "07777", accessMask(os.ModePerm|os.ModeSticky|os.ModeSetgid|os.ModeSetuid))
}
