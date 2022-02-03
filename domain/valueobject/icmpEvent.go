package valueobject

import "furui/constant"

type ICMPEvent struct {
	SAddr   uint32
	DAddr   uint32
	Version uint8
	Type    uint8
	Code    uint8
	Action  uint8
}

type ICMP6Event struct {
	SAddr   [constant.IPv6Length]byte
	DAddr   [constant.IPv6Length]byte
	Version uint8
	Type    uint8
	Code    uint8
	Action  uint8
}
