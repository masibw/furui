package entity

import (
	"fmt"
	"net"
)

type Policy struct {
	Container      *Container
	Communications []*Communication
}

func (p *Policy) String() string {
	return fmt.Sprintf("{Container: %s Communications: %v", p.Container, p.Communications)
}

type Communication struct {
	Process string
	Sockets []*Socket
	ICMP    []*ICMP
}

func (c *Communication) String() string {
	return fmt.Sprintf("{Process: %s Sockets: %v ICMP: %v", c.Process, c.Sockets, c.ICMP)
}

type Socket struct {
	Protocol   string
	LocalPort  uint16
	RemoteIP   net.IP
	RemotePort uint16
}

func (s *Socket) String() string {
	return fmt.Sprintf("{Protocol: %s LocalPort: %d RemoteHost: %s RemotePort: %d", s.Protocol, s.LocalPort, s.RemoteIP, s.RemoteIP)
}

type ICMP struct {
	Version  uint8
	Type     uint8
	Code     uint8
	RemoteIP net.IP
}

func (i *ICMP) String() string {
	return fmt.Sprintf("{Version: %d Type: %d Code: %d RemoteHost: %s", i.Version, i.Type, i.Code, i.RemoteIP)
}
