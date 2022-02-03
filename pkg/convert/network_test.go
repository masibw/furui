package convert

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"furui/domain/entity"
	"furui/driver"
	"furui/infrastructure/docker"
)

func TestRemoteHostToIPs(t *testing.T) {
	type args struct {
		remoteHost string
	}
	tests := []struct {
		name    string
		args    args
		wantIPs []net.IP
	}{
		{
			name: "Can convert docker container name to IP Addresses",
			args: args{
				remoteHost: "nginx_test",
			},
			wantIPs: []net.IP{net.ParseIP("192.168.4.2"), net.ParseIP("fd00::2:2")},
		},
	}
	dockerInfra := docker.New(driver.DockerCLI())

	containers := entity.NewContainers(nil)

	err := dockerInfra.AddRunningContainersInspect(containers)
	if err != nil {
		t.Fatalf("failed to get containers information: %+v", err)
		return
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIPs := RemoteHostToIPs(containers, tt.args.remoteHost)
			assert.Equal(t, tt.wantIPs, gotIPs)
		})
	}
}
