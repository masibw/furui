package valueobject

import "furui/constant"

type BindEvent struct {
	ContainerID [constant.ContainerIDCap]byte
	Pid         uint32
	Comm        [constant.TaskCommLen]byte
	Family      uint16
	Lport       uint16
	Proto       uint8
}
