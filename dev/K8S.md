## kubernetes setup

* use systemd group driver with kubelet

cat /etc/systemd/system/kubelet.service.d/10-kubeadm.conf

	Environment="KUBELET_CONFIG_ARGS=--config=/etc/kubelet.yaml"

kubelet config spec:

cp /var/lib/kubelet/config.yaml  /etc/kubelet.yaml
echo "cgroupDriver: systemd“ >> /etc/kubelet.yaml

https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/kubelet/config/v1beta1/types.go



kubeadm  init --cri-socket /var/run/crio/crio.sock --apiserver-advertise-address=192.168.56.103


root@container-node:~/packages/cri-o# cat /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
# Note: This dropin only works with kubeadm and kubelet v1.11+
[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_CONFIG_ARGS=--config=/tmp/kubelet.yaml"
#Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
# This is a file that "kubeadm init" and "kubeadm join" generates at runtime, populating the KUBELET_KUBEADM_ARGS variable dynamically
EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
# This is a file that the user can use for overrides of the kubelet args as a last resort. Preferably, the user should use
# the .NodeRegistration.KubeletExtraArgs object in the configuration files instead. KUBELET_EXTRA_ARGS should be sourced from this file.
EnvironmentFile=-/etc/default/kubelet
ExecStart=
ExecStart=/usr/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS



	// https://github.com/kubernetes/kubernetes/blob/a38a02792b55942177ee676a5e1993b18a8b4b0a/pkg/kubelet/apis/cri/runtime/v1alpha2/api.proto#L541
	//  // Privileged mode implies the following specific options are applied:
	// 1. All capabilities are added.
	// 2. Sensitive paths, such as kernel module paths within sysfs, are not masked.
	// 3. Any sysfs and procfs mounts are mounted RW.
	// 4. Apparmor confinement is not applied.
	// 5. Seccomp restrictions are not applied.
	// 6. The device cgroup does not restrict access to any devices.
	// 7. All devices from the host's /dev are available within the container.
	// 8. SELinux restrictions are not applied (e.g. label=disabled).
	// security
	// FIXME Kubelet does not set the 'io.kubernetes.cri-o.PrivilegedRuntime"
	// https://github.com/containers/podman/blob/8704b78a6fbb953acb6b74d1671d5ad6456bf81f/pkg/annotations/annotations.go#L64

