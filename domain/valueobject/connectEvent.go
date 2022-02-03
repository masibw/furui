package valueobject

import "furui/constant"

type ConnectEvent struct {
	ContainerID [constant.ContainerIDCap]byte
	Pid         uint32
	Comm        [constant.TaskCommLen]byte
	SAddr       uint32
	DAddr       uint32
	SPort       uint16
	DPort       uint16
	Family      uint16
	Proto       uint8
}
