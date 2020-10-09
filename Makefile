GO_SRC=$(shell find . -name \*.go)
COMMIT_HASH=$(shell git describe --always --tags --long)
COMMIT=$(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_HASH)-dirty,$(COMMIT_HASH))
TEST?=$(patsubst test/%.bats,%,$(wildcard test/*.bats))
PACKAGES_DIR?=~/packages
PKG_CONFIG := $(shell pkg-config --libs --cflags lxc)
BINS := crio-lxc crio-lxc-start crio-lxc-init crio-lxc-hook
PREFIX ?= /usr/local
CGO_ENABLED=0 
LDFLAGS=-s -w -X main.version=$(COMMIT)
INIT_LDFLAGS=$(LDFLAGS) -extldflags "-static"

all: $(BINS)

crio-lxc: $(GO_SRC) Makefile go.mod
	go build -ldflags '$(LDFLAGS)' -o $@ ./cmd

crio-lxc-init: $(GO_SRC) Makefile go.mod
	go build -ldflags '$(INIT_LDFLAGS)' -o $@ ./cmd/init

crio-lxc-hook: $(GO_SRC) Makefile go.mod
	go build -ldflags '$(INIT_LDFLAGS)' -o $@ ./cmd/hook

crio-lxc-start: cmd/start/crio-lxc-start.c
	gcc $? $(PKG_CONFIG) -o $@

install: all 
	cp $(BINS) $(PREFIX)/bin

lint:
	golangci-lint run -c ./lint.yaml ./...

# make test TEST=basic will run only the basic test.
.PHONY: check
check: crio-lxc
	go fmt ./... && ([ -z $(TRAVIS) ] || git diff --quiet)
	go test ./...
	PACKAGES_DIR=$(PACKAGES_DIR) sudo -E "PATH=$$PATH" bats -t $(patsubst %,test/%.bats,$(TEST))

test/*.bats: crio-lxc
	PACKAGES_DIR=$(PACKAGES_DIR) sudo -E "PATH=$$PATH" bats -t $@

.PHONY: vendorup
vendorup:
	go get -u

.PHONY: clean
clean:
	-rm -f $(BINS)

fmt:
	go fmt ./...
