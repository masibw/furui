package constant

const (
	// PolicyPath is the path of the policy.
	PolicyPath string = "policy.yml"

	TaskCommLen int = 16
	// ContainerIDLen is 12 bytes because docker sets the hostname to the first 12 characters of the container ID
	// https://github.com/moby/moby/blob/2773f81aa5e9e34733675a7aa7e4219391caccb0/daemon/container.go#L199-L204
	ContainerIDLen int = 12

	// ContainerIDCap is the capacity of the array considering the memory alignment
	ContainerIDCap int = 16

	// NamespaceName is the name of the namespace used for the pinning of the tc program
	NamespaceName string = "furui-namespace"

	// ProgName is the name of this program
	ProgName string = "furui"

	// NicName is the name of the network interface used for the tc program
	NicName string = "docker0"

	// IPv6Length is the byte length of a address of ipv6
	IPv6Length int = 16

	// NeighborSolicitation represents Type 135 of ICMPv6
	NeighborSolicitation uint8 = 135

	// NeighborAdvertisement represents Type 136 of ICMPv6
	NeighborAdvertisement uint8 = 136

	// ICMPv4 indicates version 4
	ICMPv4 uint8 = 4

	// ICMPv6 indicates version 6
	ICMPv6 uint8 = 6
)
