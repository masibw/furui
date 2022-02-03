package process

import (
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"golang.org/x/xerrors"

	"furui/constant"
	"furui/domain/entity"
	"furui/infrastructure/log"
	"furui/infrastructure/repository/interface/process"
	"furui/pkg/convert"
)

type Repository struct {
	Module *bpf.Module
}

type Key struct {
	containerID [constant.ContainerIDCap]byte
	port        uint16
	proto       uint8
}

func NewKey(process *entity.Process) (*Key, error) {
	id, err := convert.ContainerIDStrToASCIIBytes(process.ContainerID[:constant.ContainerIDLen])
	if err != nil {
		err = xerrors.Errorf(": %w", err)
		return nil, err
	}

	return &Key{
		containerID: id,
		port:        process.Port,
		proto:       process.Protocol,
	}, nil
}

type Value struct {
	comm [constant.TaskCommLen]byte
}

func NewProcessRepository(b *bpf.Module) process.Repository {
	return &Repository{
		Module: b,
	}
}

func (r *Repository) SaveProcesses(processes []*entity.Process) error {
	procPorts := bpf.NewTable(r.Module.TableId("proc_ports"), r.Module)
	for _, process := range processes {
		key, err := NewKey(process)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		comm, err := convert.ProcessStrToASCIIBytes(process.Executable)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		val := &Value{
			comm: comm,
		}
		log.Logger.Debugf("save process key: %+v", key)
		if err := procPorts.SetP(unsafe.Pointer(key), unsafe.Pointer(val)); err != nil {
			err = xerrors.Errorf("failed to save proc_ports: %w", err)
			return err
		}
	}
	return nil
}

func (r *Repository) DeleteProcess(process *entity.Process) error {
	procPorts := bpf.NewTable(r.Module.TableId("proc_ports"), r.Module)
	id, err := convert.ContainerIDStrToASCIIBytes(process.ContainerID[:constant.ContainerIDLen])
	if err != nil {
		err = xerrors.Errorf(": %w", err)
		return err
	}
	key := &Key{
		containerID: id,
		port:        process.Port,
		proto:       process.Protocol,
	}

	log.Logger.Debugf("delete key: %+v, fd: %+v", key, procPorts.Fd())
	if err = procPorts.DeleteP(unsafe.Pointer(key)); err != nil {
		err = xerrors.Errorf("failed to delete proc_ports: %w", err)
		return err
	}

	return nil
}
