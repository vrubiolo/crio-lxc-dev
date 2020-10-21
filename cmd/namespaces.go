package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

type Namespace struct {
	Name      string
	CloneFlag int
}

// maps from CRIO namespace names to LXC names and clone flags
var NamespaceMap = map[specs.LinuxNamespaceType]Namespace{
	specs.CgroupNamespace:  Namespace{"cgroup", unix.CLONE_NEWCGROUP},
	specs.IPCNamespace:     Namespace{"ipc", unix.CLONE_NEWIPC},
	specs.MountNamespace:   Namespace{"mnt", unix.CLONE_NEWNS},
	specs.NetworkNamespace: Namespace{"net", unix.CLONE_NEWNET},
	specs.PIDNamespace:     Namespace{"pid", unix.CLONE_NEWPID},
	specs.UserNamespace:    Namespace{"user", unix.CLONE_NEWUSER},
	specs.UTSNamespace:     Namespace{"uts", unix.CLONE_NEWUTS},
}

func configureNamespaces(namespaces []specs.LinuxNamespace) error {
	procPidPathRE := regexp.MustCompile(`/proc/(\d+)/ns`)

	var configVal string
	seenNamespaceTypes := map[specs.LinuxNamespaceType]bool{}
	for _, ns := range namespaces {
		if _, ok := seenNamespaceTypes[ns.Type]; ok {
			return fmt.Errorf("duplicate namespace type %s", ns.Type)
		}
		seenNamespaceTypes[ns.Type] = true
		if ns.Path == "" {
			continue
		}

		n, supported := NamespaceMap[ns.Type]
		if !supported {
			return fmt.Errorf("Unsupported namespace %s", ns.Type)
		}
		configKey := fmt.Sprintf("lxc.namespace.share.%s", n.Name)

		matches := procPidPathRE.FindStringSubmatch(ns.Path)
		switch len(matches) {
		case 0:
			configVal = ns.Path
		case 1:
			return fmt.Errorf("error parsing namespace path. expected /proc/(\\d+)/ns/*, got '%s'", ns.Path)
		case 2:
			configVal = matches[1]
		default:
			return fmt.Errorf("error parsing namespace path. expected /proc/(\\d+)/ns/*, got '%s'", ns.Path)
		}

		if err := clxc.SetConfigItem(configKey, configVal); err != nil {
			return err
		}
	}

	// from `man lxc.container.conf` - user and network namespace must be inherited together
	if !seenNamespaceTypes[specs.NetworkNamespace] && seenNamespaceTypes[specs.UserNamespace] {
		return fmt.Errorf("to inherit the network namespace the user namespace must be inherited as well")
	}

	nsToKeep := make([]string, 0, len(NamespaceMap))
	for key, n := range NamespaceMap {
		if !seenNamespaceTypes[key] {
			nsToKeep = append(nsToKeep, n.Name)
		}
	}
	return clxc.SetConfigItem("lxc.namespace.keep", strings.Join(nsToKeep, " "))
}

func isNamespaceEnabled(spec *specs.Spec, nsType specs.LinuxNamespaceType) bool {
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == nsType {
			return true
		}
	}
	return false
}
