PKG_CONFIG := $(shell pkg-config --libs --cflags lxc)
ALL := crio-lxc-start

all: $(ALL)

crio-lxc-kill: crio-lxc-kill.c
	gcc $? $(PKG_CONFIG) -o $@

crio-lxc-start: crio-lxc-start.c
	gcc $? $(PKG_CONFIG) -o $@

clean:
	rm $(ALL)
