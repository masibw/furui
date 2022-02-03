package valueobject

import "furui/constant"

type Connect6Event struct {
	ContainerID [constant.ContainerIDCap]byte
	Pid         uint32
	Comm        [constant.TaskCommLen]byte
	SAddr       [constant.IPv6Length]byte
	DAddr       [constant.IPv6Length]byte
	SPort       uint16
	DPort       uint16
	Family      uint16
	Proto       uint8
}
