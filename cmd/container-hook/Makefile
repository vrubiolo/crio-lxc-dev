hook: hook.c
	/usr/local/musl/bin/musl-gcc -Wpedantic -Wall  -static -g -o hook hook.c

test: hook
	 LXC_ROOTFS_MOUNT=. LXC_CONFIG_FILE=./config gdb ./hook
