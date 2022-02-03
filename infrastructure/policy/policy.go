package policy

import (
	"golang.org/x/xerrors"

	"furui/domain/entity"
)

// LoadPolicy loads policy from file and returns policy slice.
func LoadPolicy(path string, containers *entity.Containers) (policies []*entity.Policy, err error) {
	parser := NewYamlParser()
	var rawPolicyData []byte
	rawPolicyData, err = parser.Load(path)
	if err != nil {
		err = xerrors.Errorf(": %w", err)
		return
	}

	policies, err = parser.Parse(rawPolicyData, containers)
	if err != nil {
		err = xerrors.Errorf(": %w", err)
		return
	}
	return
}
