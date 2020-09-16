module github.com/lxc/crio-lxc

require (
	github.com/apex/log v1.9.0
	github.com/creack/pty v1.1.11
	github.com/opencontainers/runtime-spec v1.0.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.6.1
	github.com/u-root/u-root v6.0.0+incompatible
	github.com/urfave/cli v1.22.4
	golang.org/x/sys v0.0.0-20200831180312-196b9ba8737a
	gopkg.in/lxc/go-lxc.v2 v2.0.0-20200826211823-2dd0dc9c018b
)

replace github.com/vbatts/go-mtree v0.4.4 => github.com/vbatts/go-mtree v0.4.5-0.20190122034725-8b6de6073c1a

replace github.com/openSUSE/umoci v0.4.4 => github.com/tych0/umoci v0.1.1-0.20190402232331-556620754fb1

go 1.13
