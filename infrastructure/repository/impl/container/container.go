package container

import (
	"encoding/binary"
	"net"
	"strings"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"golang.org/x/xerrors"

	"furui/constant"
	"furui/domain/entity"
	"furui/infrastructure/repository/interface/container"
	"furui/pkg/convert"
)

type Repository struct {
	Module *bpf.Module
}

func NewContainerRepository(b *bpf.Module) container.Repository {
	return &Repository{
		Module: b,
	}
}

type Key struct {
	ip   uint32
	ipv6 [constant.IPv6Length]byte
}

func NewKey(ip net.IP) *Key {
	k := &Key{}

	if strings.Count(ip.String(), ":") < 2 {
		k.ip = binary.LittleEndian.Uint32(ip[12:16])
	} else if strings.Count(ip.String(), ":") >= 2 {
		copy(k.ipv6[:], ip)
	}
	return k
}

type Value struct {
	ContainerID [constant.ContainerIDCap]byte
}

// SaveIDWithIPs saves the IP address of the network byte order with the container ID.
func (r *Repository) SaveIDWithIPs(containers *entity.Containers) error {
	idFromIPs := bpf.NewTable(r.Module.TableId("container_id_from_ips"), r.Module)
	for _, container := range containers.List() {
		id, err := convert.ContainerIDStrToASCIIBytes(container.ID[:constant.ContainerIDLen])
		if err != nil {
			err = xerrors.Errorf(": %w", err)
			return err
		}

		for _, ip := range container.IPAddresses {
			k := NewKey(ip)

			v := &Value{
				ContainerID: id,
			}
			if err := idFromIPs.SetP(unsafe.Pointer(k), unsafe.Pointer(v)); err != nil {
				err = xerrors.Errorf("failed to save id from ips: %w", err)
				return err
			}
		}
	}
	return nil
}

func (r Repository) RemoveIDFromIPs(container *entity.Container) error {
	idFromIPs := bpf.NewTable(r.Module.TableId("container_id_from_ips"), r.Module)

	for _, ip := range container.IPAddresses {
		k := NewKey(ip)

		if err := idFromIPs.DeleteP(unsafe.Pointer(k)); err != nil {
			err = xerrors.Errorf("failed to save id from ips: %w", err)
			return err
		}
	}
	return nil
}
