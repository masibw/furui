package nic

import (
	"net"
	"strings"

	"golang.org/x/xerrors"
)

func GetNamesConnectedToContainers() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		err = xerrors.Errorf(": %w", err)
		return nil, err
	}
	res := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "veth") {
			res = append(res, iface.Name)
		}
	}
	return res, nil
}
