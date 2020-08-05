#!/bin/sh
LOG=/tmp/crio-lxc.log.$$
ARGS=$@
NEWARGS="--debug --log-level DEBUG --log-file $LOG $ARGS"
SPEC=$(echo "$ARGS" | grep -o /tmp/exec-process-[0-9]*)

cat > $LOG <<EOF
----
$(env)
----
ARGS:$ARGS
NEWARGS:$NEWARGS
SPEC:$SPEC
----
EOF

if [ -n "$SPEC" ] && [ -f $SPEC ]; then
	cp -v $SPEC $LOG.spec.json >> $LOG 2>&1 
fi

exec /usr/local/bin/crio-lxc $NEWARGS 
