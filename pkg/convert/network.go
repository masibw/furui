package convert

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	"furui/domain/entity"
	"furui/infrastructure/log"
)

func ProtoToString(proto uint8) (protocol string) {
	if proto == syscall.IPPROTO_IP {
		protocol = "IP"
	} else if proto == syscall.IPPROTO_TCP {
		protocol = "TCP"
	} else if proto == syscall.IPPROTO_UDP {
		protocol = "UDP"
	} else if proto == syscall.IPPROTO_ICMP {
		protocol = "ICMP"
	} else {
		protocol = "UNK"
	}

	return
}

func StringToProto(proto string) (protocol uint8) {
	proto = strings.ToLower(proto)
	if proto == "ip" {
		protocol = syscall.IPPROTO_IP
	} else if proto == "tcp" || proto == "tcp6" {
		protocol = syscall.IPPROTO_TCP
	} else if proto == "udp" || proto == "udp6" {
		protocol = syscall.IPPROTO_UDP
	} else {
		// 255 is defined as Error(UNKNOWN)
		protocol = 255
	}
	return
}

func IPVersionToString(protoFamily uint16) (IPVersion string) {
	if protoFamily == syscall.AF_INET {
		IPVersion = "v4"
	} else if protoFamily == syscall.AF_INET6 {
		IPVersion = "v6"
	}
	return
}

func Ntoa(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func RemoteHostToIPs(containers *entity.Containers, remoteHost string) (IPs []net.IP) {
	if remoteHost == "" {
		return
	}

	if ip := net.ParseIP(remoteHost); ip != nil {
		remoteIP := net.ParseIP(remoteHost)
		IPs = []net.IP{remoteIP}
		return
	} else {
		addrsStr, err := net.LookupHost(remoteHost)
		if err != nil {
			container := containers.GetFromName(remoteHost)
			if container == nil {
				log.Logger.Warnf("failed to look up host: %s err: %+v", remoteHost, err)
				return
			}
			err = nil //nolint:ineffassign
			IPs = container.IPAddresses
		} else {
			for _, addrStr := range addrsStr {
				IPs = append(IPs, net.ParseIP(addrStr))
			}
		}
		return
	}
}
