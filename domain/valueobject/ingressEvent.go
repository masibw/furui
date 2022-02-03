package valueobject

import "furui/constant"

type IngressEvent struct {
	SAddr  uint32
	DAddr  uint32
	SPort  uint16
	DPort  uint16
	Proto  uint8
	Action uint8
	Comm   [constant.TaskCommLen]byte
}

type Ingress6Event struct {
	SAddr  [constant.IPv6Length]byte
	DAddr  [constant.IPv6Length]byte
	SPort  uint16
	DPort  uint16
	Proto  uint8
	Action uint8
	Comm   [constant.TaskCommLen]byte
}
