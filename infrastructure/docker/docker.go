package docker

import (
	"context"
	"net"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"golang.org/x/xerrors"

	"furui/constant"
	"furui/domain/entity"
)

type Docker interface {
	SetContainerInspect(m *entity.Container, cid string) error
	AddRunningContainersInspect(containers *entity.Containers) error
}

type docker struct {
	cli *client.Client
}

func New(dockerCLI *client.Client) Docker {
	return &docker{cli: dockerCLI}
}

// SetContainerInspect sets the container's detailed information to a structure
func (i docker) SetContainerInspect(m *entity.Container, cid string) error {
	inspect, err := i.cli.ContainerInspect(context.Background(), cid)
	if err != nil {
		return xerrors.Errorf("failed to inspect container: %w", err)
	}

	ipAddresses := make([]net.IP, 0, len(inspect.NetworkSettings.Networks))
	for _, network := range inspect.NetworkSettings.Networks {
		ipv4 := net.ParseIP(network.IPAddress)
		ipv6 := net.ParseIP(network.GlobalIPv6Address)
		if ipv4 != nil {
			ipAddresses = append(ipAddresses, ipv4)
		}
		if ipv6 != nil {
			ipAddresses = append(ipAddresses, ipv6)
		}
	}

	m.ID = inspect.ID[:constant.ContainerIDLen]
	m.IPAddresses = ipAddresses
	m.Pid = inspect.State.Pid
	m.Name = inspect.Name

	return nil
}

// AddRunningContainersInspect returns a list of docker containers that are currently running.
func (i docker) AddRunningContainersInspect(containers *entity.Containers) error {
	dockerContainers, err := i.cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return xerrors.Errorf("failed to get container list: %w", err)
	}

	for _, dockerContainer := range dockerContainers {
		container := entity.NewContainer()

		err = i.SetContainerInspect(container, dockerContainer.ID)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		containers.Add(container)
	}

	return nil
}
