package cmd

import (
	"os"
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"furui/domain/entity"
	"furui/infrastructure/log"
	processRepo "furui/infrastructure/repository/interface/process"

	"go.uber.org/zap"
	zapobserver "go.uber.org/zap/zaptest/observer"
)

// readFile opens a file at the specified path and returns []bytes
func readFile(t *testing.T, path string) (p []byte) {
	t.Helper()
	var err error
	p, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to open file path: %s, err: %s", path, err)
		return nil
	}
	return
}

// extractLog returns the message as a string in the Log.
func extractLog(t *testing.T, fnc func(start chan string, processRepository processRepo.Repository, processes []*entity.Process) (func(), error), sig chan os.Signal, start chan string, processRepository processRepo.Repository, processes []*entity.Process) (string, error) {
	t.Helper()

	// Make it possible to retrieve and handle the logs spit out by zap
	core, obs := zapobserver.New(zap.InfoLevel)

	logger := zap.New(core)
	// Replace logger
	log.Logger = log.NewZapLogger(logger)

	// Execute the function under test.

	clean, err := fnc(start, processRepository, processes)
	if err != nil {
		t.Log("err: ", err)
		return "", err
	}
loop:
	for { //nolint:gosimple
		select {
		case <-sig:
			break loop
		}
	}
	t.Cleanup(func() {
		clean()
	})

	// Extracts only the message and concatenates it into a single string.
	all := obs.All()
	res := make([]byte, 0, len(all))
	for _, each := range all {
		res = append(res, each.Message...)
	}

	return *(*string)(unsafe.Pointer(&res)), nil
}

//  runAnotherNameSpace will run the command passed as argument in another namespace
func runAnotherNameSpace(t *testing.T, doRunInContainer bool, args ...string) {
	t.Helper()
	var cmd *exec.Cmd
	if doRunInContainer {
		args = append([]string{"--pid", "--fork"}, args...)
		// Run with the unshare command to isolate the namespace
		cmd = exec.Command("unshare", args...)
	} else {
		// Execute commands without isolating namespace
		cmd = exec.Command(args[0], args[1:]...) // #nosec //It's a test, so it's not a problem.

	}

	err := cmd.Start()
	if err != nil {
		t.Fatalf("Error running the command [unshare --pid %s] err: %s\n", args, err)
		return
	}

	time.Sleep(1 * time.Second)
	err = cmd.Process.Kill()
	if err != nil {
		t.Fatalf("failed to kill the cmd: %s err: %s\n", cmd, err)
		return
	}
}
