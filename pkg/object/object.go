package object

import (
	"fmt"
	"os/exec"

	"github.com/iovisor/gobpf/elf"
	"golang.org/x/xerrors"

	"furui/constant"
	"furui/pkg/file"
)

func Unlink(direction string) (err error) {
	_, err = exec.Command("unlink", fmt.Sprintf("/sys/fs/bpf/%s/globals/%s-%s", constant.NamespaceName, constant.ProgName, direction)).CombinedOutput() // #nosec //running it with constants, so no problem.
	if err != nil {
		err = xerrors.Errorf("failed to unlink program: %w", err)
		return
	}
	return
}

func Pin(fn int, direction string) (err error) {
	if file.Exists(fmt.Sprintf("/sys/fs/bpf/%s/globals/%s-%s", constant.NamespaceName, constant.ProgName, direction)) {
		err = Unlink(direction)
		if err != nil {
			err = xerrors.Errorf(": %w", err)
			return
		}
	}

	err = elf.PinObjectGlobal(fn, constant.NamespaceName, constant.ProgName+"-"+direction)
	if err != nil {
		err = xerrors.Errorf("failed to pin ingress program: %w", err)
		if err != nil {
			err = xerrors.Errorf("failed to unlink program: %s", err)
			return
		}
	}
	return
}
