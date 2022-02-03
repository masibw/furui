package convert

import (
	"unicode/utf8"

	"golang.org/x/xerrors"

	"furui/constant"
)

// Prepare the appropriate function for each application, because it will be an error if it is not passed to eBPF as a fixed-length array.

func stringToASCIIBytes(s string, len int) []byte {
	t := make([]byte, len)
	i := 0
	for _, r := range s {
		t[i] = byte(r)
		i++
	}
	return t
}

func ProcessStrToASCIIBytes(s string) ([constant.TaskCommLen]byte, error) {
	if utf8.RuneCountInString(s) > constant.TaskCommLen {
		return [constant.TaskCommLen]byte{}, xerrors.Errorf("executable length is over constant.TaskCommLen executable: %s", s)
	}
	t := stringToASCIIBytes(s, constant.TaskCommLen)

	var res [constant.TaskCommLen]byte
	copy(res[:], t[:constant.TaskCommLen])
	return res, nil
}

func ContainerIDStrToASCIIBytes(s string) ([constant.ContainerIDCap]byte, error) {
	if utf8.RuneCountInString(s) > constant.ContainerIDLen {
		return [constant.ContainerIDCap]byte{}, xerrors.Errorf("containerID length is over constant.ContainerIDLen: %s", s)
	}
	t := stringToASCIIBytes(s, constant.ContainerIDLen)

	var res [constant.ContainerIDCap]byte
	copy(res[:], t[:constant.ContainerIDLen])
	return res, nil
}
