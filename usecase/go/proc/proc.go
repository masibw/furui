package proc

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/xerrors"

	"furui/constant"
	"furui/domain/entity"
	"furui/infrastructure/log"
	"furui/pkg/convert"
	"furui/pkg/process"
	"furui/pkg/socket"
)

func getSupportedProtocols() (netFiles []string) {
	return []string{"tcp", "udp", "tcp6", "udp6"}
}

// searchProcessOfContainerFromInode return Process struct of the process that have specific socket inode.
func searchProcessOfContainerFromInode(containerPID int, inode uint64) (executable string, pid int, err error) {
	var containerdShimPid int
	containerdShimPid, err = process.RetrievePPID(containerPID)
	if err != nil {
		err = xerrors.Errorf("failed to retrieve PPID: %w", err)
		return
	}
	var childPIDs []int
	childPIDs, err = process.RetrieveChildPIDs(containerdShimPid)
	if err != nil {
		err = xerrors.Errorf("failed to retrieve child PIDs: %w", err)
		return
	}

	// Check inode of pids
	for _, pid = range childPIDs {
		var exist bool
		exist, err = socket.InodeExists(pid, inode)
		if err != nil {
			err = xerrors.Errorf("failed to check inode exists pid: %d, err: %w", pid, err)
			return
		}

		if exist {
			executable, err = process.RetrieveProcessName(pid)
			if err != nil {
				err = xerrors.Errorf("failed to retrieve process name: %w", err)
				return
			}

			return
		}
	}
	err = constant.ErrExecutableNotFound
	return
}

// GetProcesses returns the process waiting in the container, port number, and container ID.
func GetProcesses(containers *entity.Containers) (processes []*entity.Process) {

	for _, container := range containers.List() {

		for _, protocol := range getSupportedProtocols() {
			netFilePath := filepath.Join("/proc", strconv.Itoa(container.Pid), "net", protocol)

			file, err := os.ReadFile(netFilePath)
			if err != nil {
				log.Logger.Errorf("failed to open netFile: %s, err: %+v", netFilePath, err)
				continue
			}
			entryScanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
			entryScanner.Scan() // Skip the first line (header)
			// Read to the end of the file and get the port number and inode
			for exist := entryScanner.Scan(); exist; exist = entryScanner.Scan() {
				// Separate a line with a space
				row := strings.Fields(entryScanner.Text())

				// 0-indexed without the first IP address (e.g., 0050 of 00000000:0050)
				var port uint64
				colonIndex := strings.Index(row[1], ":")
				port, err = strconv.ParseUint(row[1][colonIndex+1:], 16, 16)
				if err != nil {
					log.Logger.Errorf("failed to hexadecimal conversion to decimal: %s, err: %+v", row[1][9:], err)
					continue
				}
				// Find the executable
				var inode uint64
				inode, err = strconv.ParseUint(row[9], 10, 64)
				if err != nil {
					log.Logger.Errorf("failed to get inode: %+v", err)
					continue
				}
				var executable string
				var pid int
				executable, pid, err = searchProcessOfContainerFromInode(container.Pid, inode)
				if err != nil {
					log.Logger.Errorf("failed to search process from container: %+v, inode: %d, err: %+v", container, inode, err)
					continue
				}
				process := &entity.Process{
					ContainerID: container.ID,
					Executable:  executable,
					Protocol:    convert.StringToProto(protocol),
					Port:        uint16(port),
					Pid:         uint32(pid),
				}
				processes = append(processes, process)
				log.Logger.Debugf("found process: %+v", process)
			}
		}
	}

	return
}
