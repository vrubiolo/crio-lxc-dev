#!/bin/sh

name="kube-controller-manager"
container=$( crictl ps --name $name --quiet)
echo "$name $container"

container_exec() {
	crictl exec -i -t $container /bin/sh -x -c "$@"
	echo "status $?"
}

#container_exec "ls /proc/acpi"
#container_exec "stat /proc/kcore"
#container_exec "cat /proc/keys"
#container_exec "rm /proc/keys"
#container_exec "ls /proc/asound"
#container_exec "ls /proc/bus"
#container_exec "ls /proc/fs"
#container_exec "ls /proc/scsi"
#container_exec "cat /proc/sched_debug"
container_exec "ls -ld /proc/irq"
container_exec "ls -l /proc/irq"
container_exec "stat /proc/irq/default_smp_affinity"
container_exec 'echo ff > /proc/irq/default_smp_affinity'
container_exec "ls -l /proc/asound"
container_exec "echo > /proc/asound/foo"
container_exec "echo b > /proc/sysrq-trigger"
container_exec "cat /proc/mounts"
container_exec "umount /proc/sysrq-trigger"
container_exec "ls /usr/bin /bin /sbin /usr/sbin"
container_exec "cat /etc/debian_version"
