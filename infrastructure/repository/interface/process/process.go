package process

import "furui/domain/entity"

type Repository interface {
	SaveProcesses(processes []*entity.Process) error
	DeleteProcess(process *entity.Process) error
}
