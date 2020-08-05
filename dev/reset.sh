#!/bin/sh
make crio-lxc || exit 1
make -C tools || exit 1
kubeadm reset --cri-socket unix:///var/run/crio/crio.sock --force
rm /tmp/crio-lxc.log.* /tmp/config.*
rm /var/log/container/*
cp -v crio-lxc /usr/local/bin || exit 1
cp -v tools/crio-lxc-start /usr/local/bin || exit 1
if kubeadm  init --cri-socket unix://var/run/crio/crio.sock --apiserver-advertise-address=192.168.56.106 --control-plane-endpoint k8s-controller -v 5; then
	cp /etc/kubernetes/admin.conf $HOME/.kube/config
	kubectl taint nodes --all node-role.kubernetes.io/master-
fi
