module furui

go 1.16

require (
	github.com/containerd/containerd v1.5.4 // indirect
	github.com/docker/docker v20.10.7+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/iovisor/gobpf v0.2.0
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/thoas/go-funk v0.9.1
	go.uber.org/zap v1.17.0
	golang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4 // indirect
	golang.org/x/sys v0.0.0-20210510120138-977fb7262007 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/iovisor/gobpf => github.com/masibw/gobpf v0.1.2-0.20210703012115-52118d0ca0ea
