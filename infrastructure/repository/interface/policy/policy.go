package policy

import "furui/domain/entity"

type Repository interface {
	Save(policies []*entity.Policy) error
	Delete(EPolicies []*entity.Policy) error
}
