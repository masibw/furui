package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"furui/domain/entity"
)

func TestArrangePolicy(t *testing.T) {
	type args struct {
		policies   []*entity.Policy
		containers *entity.Containers
	}
	tests := []struct {
		name          string
		args          args
		wantResPolicy []*entity.Policy
		wantErr       bool
	}{
		{
			name: "ID will be set.",
			args: args{
				policies: []*entity.Policy{
					{
						Container: &entity.Container{
							Name: "container_name",
						},
					},
				},
				containers: entity.NewContainers(
					[]*entity.Container{
						{
							ID:   "container_id",
							Name: "/container_name",
						},
					},
				),
			},
			wantResPolicy: []*entity.Policy{
				{
					Container: &entity.Container{
						ID:   "container_id",
						Name: "container_name",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResPolicy, err := ArrangePolicy(tt.args.policies, tt.args.containers)
			if (err != nil) != tt.wantErr {
				t.Errorf("ArrangePolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.wantResPolicy, gotResPolicy)
		})
	}
}
