GO_SRC=$(shell find . -name \*.go)
COMMIT_HASH=$(shell git describe --always --tags --long)
COMMIT=$(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_HASH)-dirty,$(COMMIT_HASH))
TEST?=$(patsubst test/%.bats,%,$(wildcard test/*.bats))
PACKAGES_DIR?=~/packages

default: crio-lxc

crio-lxc: $(GO_SRC) Makefile go.mod
	go build -ldflags "-X main.version=$(COMMIT)" -o crio-lxc ./cmd
	go build -ldflags "-X main.version=$(COMMIT)" -o crio-lxc-init ./init

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
	-rm -f crio-lxc
