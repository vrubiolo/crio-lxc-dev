#!/bin/sh
make crio-lxc || exit 1
make -C tools || exit 1
kubeadm reset --cri-socket unix:///var/run/crio/crio.sock --force
rm /tmp/crio-lxc.log.* /tmp/config.*
rm /tmp/busybox.log
cp -v crio-lxc /usr/local/bin || exit 1
cp -v tools/crio-lxc-start tools/crio-lxc-kill /usr/local/bin || exit 1
pod=$(crictl runp dev/pod.json)
echo $pod
crictl pull busybox
container=$(crictl create $pod dev/container.json dev/pod.json)
crictl start $container
sleep 2
crictl logs $container
