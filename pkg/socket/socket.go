package socket

import (
	"golang.org/x/xerrors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// InodeExists reports whether the process has socket inode.
func InodeExists(pid int, inode uint64) (exist bool, err error) {

	fdDirPath := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fdFiles, err := ioutil.ReadDir(fdDirPath)
	if err != nil {
		err = xerrors.Errorf("failed to readDir: %s, err: %w", fdDirPath, err)
		return
	}
	for _, fdFile := range fdFiles {
		var linkContent string
		linkContent, err = os.Readlink(filepath.Join(fdDirPath, fdFile.Name()))
		if err != nil {
			err = xerrors.Errorf("failed to readLink: %s, err: %w", linkContent, err)
			return
		}
		if strings.HasPrefix(linkContent, "socket") && linkContent[8:len(linkContent)-1] == strconv.FormatUint(inode, 10) {
			exist = true
			return
		}
	}

	return
}
