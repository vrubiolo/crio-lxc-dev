#!/bin/sh
pod=$(crictl runp dev/pod.json)
container=$(crictl create $pod dev/container1.json dev/pod.json)
crictl start $container
