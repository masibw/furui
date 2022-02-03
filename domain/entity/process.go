package entity

type Process struct {
	ContainerID string
	Executable  string
	Protocol    uint8
	Port        uint16
	Pid         uint32
}
