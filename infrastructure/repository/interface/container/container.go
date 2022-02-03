package container

import "furui/domain/entity"

type Repository interface {
	SaveIDWithIPs(containers *entity.Containers) error
	RemoveIDFromIPs(container *entity.Container) error
}
