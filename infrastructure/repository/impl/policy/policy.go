package policy

import (
	"encoding/binary"
	"strings"
	"unsafe"

	"furui/constant"
	"furui/domain/entity"
	"furui/infrastructure/log"
	"furui/infrastructure/repository/interface/policy"
	"furui/pkg/convert"

	bpf "github.com/iovisor/gobpf/bcc"

	"golang.org/x/xerrors"
)

type Key struct {
	ContainerID [constant.ContainerIDCap]byte
	Executable  [constant.TaskCommLen]byte
	RemoteIP    uint32
	RemoteIPv6  [constant.IPv6Length]byte
	LocalPort   uint16
	RemotePort  uint16
	Protocol    uint8
}

type Value struct {
	Executable [constant.TaskCommLen]byte
	RemoteIP   uint32
	RemoteIPv6 [constant.IPv6Length]byte
	LocalPort  uint16
	RemotePort uint16
	Protocol   uint8
}

type IcmpKey struct {
	ContainerID [constant.ContainerIDCap]byte
	Version     uint8
	Type        uint8
	Code        uint8
	RemoteIP    uint32
	RemoteIPv6  [constant.IPv6Length]byte
}

type IcmpValue struct {
	Version    uint8
	Type       uint8
	Code       uint8
	RemoteIP   uint32
	RemoteIPv6 [constant.IPv6Length]byte
}

type Repository struct {
	Module *bpf.Module
	ICMP   *bpf.Module
}

func NewPolicyRepository(b, i *bpf.Module) policy.Repository {
	return &Repository{
		Module: b,
		ICMP:   i,
	}
}

func (r *Repository) Save(EPolicies []*entity.Policy) error {
	policyList := bpf.NewTable(r.Module.TableId("policy_list"), r.Module)
	ICMPPolicyList := bpf.NewTable(r.ICMP.TableId("icmp_policy_list"), r.ICMP)

	for _, ep := range EPolicies {
		containerIDAscii, err := convert.ContainerIDStrToASCIIBytes(ep.Container.ID)
		if err != nil {
			err = xerrors.Errorf(": %w", err)
			return err
		}
		for _, communication := range ep.Communications {
			processASCII, err := convert.ProcessStrToASCIIBytes(communication.Process)
			if err != nil {
				err = xerrors.Errorf(": %w", err)
				return err
			}
			policy := &Value{
				Executable: processASCII,
			}
			key := &Key{
				ContainerID: containerIDAscii,
				Executable:  processASCII,
			}
			// If no socket information is listed, allow all communication to the process.
			if len(communication.Sockets) == 0 && len(communication.ICMP) == 0 && communication.Process != "" {
				log.Logger.Debugf("no sockets policy key: %+v, val: %+v", key, policy)
				err = policyList.SetP(unsafe.Pointer(key), unsafe.Pointer(policy))
				if err != nil {
					err = xerrors.Errorf(": %w", err)
					return err
				}
			}

			for _, socket := range communication.Sockets {
				protocol := convert.StringToProto(socket.Protocol)
				policy.LocalPort = socket.LocalPort
				policy.RemotePort = socket.RemotePort
				policy.Protocol = protocol

				key.LocalPort = socket.LocalPort
				key.RemotePort = socket.RemotePort
				key.Protocol = protocol
				if socket.RemoteIP != nil && strings.Count(socket.RemoteIP.String(), ":") < 2 {
					policy.RemoteIP = binary.LittleEndian.Uint32(socket.RemoteIP[12:16])
					key.RemoteIP = binary.LittleEndian.Uint32(socket.RemoteIP[12:16])
				} else if strings.Count(socket.RemoteIP.String(), ":") >= 2 {
					copy(key.RemoteIPv6[:], socket.RemoteIP)
					copy(policy.RemoteIPv6[:], socket.RemoteIP)
				} else {
					key.RemoteIP = 0
					policy.RemoteIP = 0
				}
				log.Logger.Debugf("policy key: %+v, val: %+v", key, policy)
				err = policyList.SetP(unsafe.Pointer(key), unsafe.Pointer(policy))
				if err != nil {
					err = xerrors.Errorf(": %w", err)
					return err
				}
			}

			for _, ICMP := range communication.ICMP {
				icmpPolicy := &IcmpValue{
					Type: ICMP.Type,
					Code: ICMP.Code,
				}

				icmpKey := &IcmpKey{
					ContainerID: containerIDAscii,
					Type:        ICMP.Type,
					Code:        ICMP.Code,
				}

				if ICMP.Version == constant.ICMPv4 || ICMP.Version == constant.ICMPv6 {
					icmpKey.Version = ICMP.Version
					icmpPolicy.Version = ICMP.Version
				} else {
					err = xerrors.Errorf("Please specify version in the policy")
					return err
				}

				if ICMP.RemoteIP != nil && strings.Count(ICMP.RemoteIP.String(), ":") < 2 {
					icmpPolicy.RemoteIP = binary.LittleEndian.Uint32(ICMP.RemoteIP[12:16])
					icmpKey.RemoteIP = binary.LittleEndian.Uint32(ICMP.RemoteIP[12:16])
				} else if strings.Count(ICMP.RemoteIP.String(), ":") >= 2 {
					copy(icmpKey.RemoteIPv6[:], ICMP.RemoteIP)
					copy(icmpPolicy.RemoteIPv6[:], ICMP.RemoteIP)
				} else {
					icmpKey.RemoteIP = 0
					icmpPolicy.RemoteIP = 0
				}

				log.Logger.Debugf("icmp policy key: %+v, val: %+v", icmpKey, icmpPolicy)
				err := ICMPPolicyList.SetP(unsafe.Pointer(icmpKey), unsafe.Pointer(icmpPolicy))
				if err != nil {
					err = xerrors.Errorf(": %w", err)
					return err
				}
			}
		}
	}
	return nil
}

func (r *Repository) Delete(EPolicies []*entity.Policy) error {
	policyList := bpf.NewTable(r.Module.TableId("policy_list"), r.Module)
	ICMPPolicyList := bpf.NewTable(r.ICMP.TableId("icmp_policy_list"), r.ICMP)

	for _, ep := range EPolicies {
		containerIDAscii, err := convert.ContainerIDStrToASCIIBytes(ep.Container.ID)
		if err != nil {
			err = xerrors.Errorf(": %w", err)
			return err
		}
		for _, communication := range ep.Communications {
			processASCII, err := convert.ProcessStrToASCIIBytes(communication.Process)
			if err != nil {
				err = xerrors.Errorf(": %w", err)
				return err
			}

			policy := &Value{
				Executable: processASCII,
			}
			key := &Key{
				ContainerID: containerIDAscii,
				Executable:  processASCII,
			}

			// ソケット情報が記載されていない場合，そのプロセスに全ての通信を許可する
			if len(communication.Sockets) == 0 && len(communication.ICMP) == 0 && communication.Process != "" {
				log.Logger.Debugf("delete policy key: %+v", key)
				err = policyList.DeleteP(unsafe.Pointer(key))
				if err != nil {
					err = xerrors.Errorf(": %w", err)
					return err
				}
			}

			for _, socket := range communication.Sockets {
				protocol := convert.StringToProto(socket.Protocol)
				policy.LocalPort = socket.LocalPort
				policy.RemotePort = socket.RemotePort
				policy.Protocol = protocol

				key.LocalPort = socket.LocalPort
				key.RemotePort = socket.RemotePort
				key.Protocol = protocol
				if socket.RemoteIP != nil && strings.Count(socket.RemoteIP.String(), ":") < 2 {
					policy.RemoteIP = binary.LittleEndian.Uint32(socket.RemoteIP[12:16])
					key.RemoteIP = binary.LittleEndian.Uint32(socket.RemoteIP[12:16])
				} else if strings.Count(socket.RemoteIP.String(), ":") >= 2 {
					copy(key.RemoteIPv6[:], socket.RemoteIP)
					copy(policy.RemoteIPv6[:], socket.RemoteIP)
				} else {
					key.RemoteIP = 0
					policy.RemoteIP = 0
				}

				log.Logger.Debugf("delete policy. key: %+v", key)
				err := policyList.DeleteP(unsafe.Pointer(key))
				if err != nil {
					err = xerrors.Errorf(": %w", err)
					return err
				}
			}
			for _, ICMP := range communication.ICMP {
				icmpPolicy := &IcmpValue{
					Type: ICMP.Type,
					Code: ICMP.Code,
				}

				icmpKey := &IcmpKey{
					ContainerID: containerIDAscii,
					Type:        ICMP.Type,
					Code:        ICMP.Code,
				}

				if ICMP.Version == constant.ICMPv4 || ICMP.Version == constant.ICMPv6 {
					icmpKey.Version = ICMP.Version
					icmpPolicy.Version = ICMP.Version
				} else {
					err = xerrors.Errorf("Please specify version in the policy")
					return err
				}

				if ICMP.RemoteIP != nil && strings.Count(ICMP.RemoteIP.String(), ":") < 2 {
					icmpPolicy.RemoteIP = binary.LittleEndian.Uint32(ICMP.RemoteIP[12:16])
					icmpKey.RemoteIP = binary.LittleEndian.Uint32(ICMP.RemoteIP[12:16])
				} else if strings.Count(ICMP.RemoteIP.String(), ":") >= 2 {
					copy(icmpKey.RemoteIPv6[:], ICMP.RemoteIP)
					copy(icmpPolicy.RemoteIPv6[:], ICMP.RemoteIP)
				} else {
					icmpKey.RemoteIP = 0
					icmpPolicy.RemoteIP = 0
				}
				log.Logger.Debugf("delete icmp policy key: %+v", icmpKey)
				err := ICMPPolicyList.DeleteP(unsafe.Pointer(icmpKey))
				if err != nil {
					err = xerrors.Errorf(": %w", err)
					return err
				}
			}
		}
	}

	return nil
}
