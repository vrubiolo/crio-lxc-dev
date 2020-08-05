#!/bin/sh
make crio-lxc || exit 1
kubeadm reset --cri-socket unix:///var/run/crio/crio.sock --force
rm /tmp/crio-lxc.log.* /tmp/config.*
cp -v crio-lxc /usr/local/bin || exit 1
if kubeadm  init --cri-socket unix://var/run/crio/crio.sock --apiserver-advertise-address=192.168.56.103 --control-plane-endpoint k8s-control-plane -v 5; then
	cp /etc/kubernetes/admin.conf $HOME/.kube/config
	kubectl taint nodes --all node-role.kubernetes.io/master-
fi
