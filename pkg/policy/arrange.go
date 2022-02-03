package policy

import (
	"strings"

	"golang.org/x/xerrors"

	"furui/domain/entity"
)

func createNameIDMap(containers []*entity.Container) map[string]string {
	nameIDMap := make(map[string]string, len(containers))
	for _, container := range containers {
		if len(container.Name) < 1 {
			continue
		}
		name := container.Name
		// Name is with / like /nginx, so skip one character
		if strings.HasPrefix(container.Name, "/") {
			name = name[1:]
		}
		nameIDMap[name] = container.ID
	}
	return nameIDMap
}

// ArrangePolicy gets the ID from the Name and checks if there is really a container with the ID.
func ArrangePolicy(policies []*entity.Policy, containers *entity.Containers) (resPolicy []*entity.Policy, err error) {
	nameIDMap := createNameIDMap(containers.List())
	for _, policy := range policies {

		if policy.Container.Name == "" {
			err = xerrors.Errorf("failed to get container's ID and Name (you need to specify the Name.)")
			return
		}

		id, ok := nameIDMap[policy.Container.Name]
		if !ok {
			err = xerrors.Errorf("failed to find specified container name: %s", policy.Container.Name)
			return
		}
		policy.Container.ID = id
	}

	resPolicy = policies
	return
}
