package process

import (
	"bufio"
	"golang.org/x/xerrors"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"
)

// RetrievePPID gets the PPID from stat of proc filesystem.
func RetrievePPID(pid int) (ppid int, err error) {

	var file []byte
	path := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	file, err = ioutil.ReadFile(path)
	if err != nil {
		err = xerrors.Errorf("failed to open stat file: %s, err: %w", path, err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	scanner.Split(bufio.ScanWords)
	for i := 0; scanner.Scan(); i++ {
		if i == 3 {
			ppid, err = strconv.Atoi(scanner.Text())
			break
		}
	}

	return
}

// RetrieveChildPIDs gets recursively child PIDs from children of proc filesystem.
func RetrieveChildPIDs(pid int) (childPIDSlice []int, err error) {

	var searchPIDStack pidStack

	// procfs children method (not exactly)
	var retrievedChildren []int
	for {
		retrievedChildren, err = retrieveChildren(pid)
		if err != nil {
			err = xerrors.Errorf("failed to retrieve the child pids: %d", pid)
			return
		}
		searchPIDStack.Push(retrievedChildren...)
		if searchPIDStack.Len() == 0 {
			break
		}
		pid = searchPIDStack.Pop()
		childPIDSlice = append(childPIDSlice, pid)
	}

	return
}

// retrieveChildren gets the child processes from children of process filesystem.
func retrieveChildren(pid int) (result []int, err error) {

	pidStr := strconv.Itoa(pid)
	var file []byte
	path := filepath.Join("/proc", pidStr, "task", pidStr, "children")
	file, err = ioutil.ReadFile(path)
	if err != nil {
		err = xerrors.Errorf("failed to open file: %s, err: %w", path, err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		var childPid int
		childPid, err = strconv.Atoi(scanner.Text())
		if err != nil {
			err = xerrors.Errorf("failed to retrieve the children: %w", err)
			return
		}
		result = append(result, childPid)
	}
	return
}
