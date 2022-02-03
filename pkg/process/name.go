package process

import (
	"golang.org/x/xerrors"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"
)

// RetrieveProcessName gets the process name from stat of process filesystem.
func RetrieveProcessName(pid int) (executable string, err error) {

	var commFile []byte
	path := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	commFile, err = ioutil.ReadFile(path)
	if err != nil {
		err = xerrors.Errorf("failed to open comm file: %s, err: %w", path, err)
		return
	}
	executable = strings.TrimSuffix(*(*string)(unsafe.Pointer(&commFile)), "\n")
	return
}
