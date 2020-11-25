#!/bin/sh

[ -f "$LXC_CONFIG_FILE" ] || exit 1
[ -d "$LXC_ROOTFS_MOUNT" ] || exit 2

RUN=$(dirname $LXC_CONFIG_FILE)

cd $LXC_ROOTFS_MOUNT

if [ -f $RUN/devices.txt ]; then
  while read line; do
    devpath=$(echo $line | cut -d ' ' -f1)
    dev=$(echo $line | cut -d ' ' -f1-4)
    filemode=$(echo $line | cut -d ' ' -f5)
    owner=$(echo $line | cut -d ' ' -f6)
    mknod .$dev || exit 3
    chmod $filemode .$devpath || exit 4
    chown $owner .$devpath || exit 5
  done <$RUN/devices.txt
fi

if [ -f $RUN/masked.txt ]; then
  for p in $(cat $RUN/masked.txt); do
    echo $masked 
    #mount
#    117   err := unix.Mount("/dev/null", p, "", unix.MS_BIND, "")
#118   if os.IsNotExist(err) {
#119     return nil
#120   }
#121   if err == unix.ENOTDIR {
#122     return unix.Mount("tmpfs", p, "tmpfs", unix.MS_RDONLY, "")
#123   }
#124   return err
  done
fi

# chmod ? chown ?
