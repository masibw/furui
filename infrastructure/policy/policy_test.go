package policy

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"

	"furui/domain/entity"
	"furui/driver"
	"furui/infrastructure/docker"
)

func TestMain(m *testing.M) {
	code := m.Run()

	os.Exit(code)
}

// preparePolicy write policy to file(testPolicy.yml) and remove it after the test.
func preparePolicy(t *testing.T, policy string) (path string) {
	tmpPolicyFile, err := ioutil.TempFile("", "testPolicy.yml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		tmpPolicyFile.Close()
		os.Remove(tmpPolicyFile.Name())
	})
	if _, err := tmpPolicyFile.Write(*(*[]byte)(unsafe.Pointer(&policy))); err != nil {
		t.Fatal(err)
	}
	return tmpPolicyFile.Name()
}

func TestLoadPolicy(t *testing.T) {
	// infrastructure
	dockerInfra := docker.New(driver.DockerCLI())

	containers := entity.NewContainers(nil)

	err := dockerInfra.AddRunningContainersInspect(containers)
	if err != nil {
		t.Fatalf("failed to get containers information: %+v", err)
		return
	}
	container := containers.GetFromName("nginx_test")
	ipv4 := container.IPAddresses[0]
	ipv6 := container.IPAddresses[1]

	type args struct {
		path string
	}
	tests := []struct {
		name         string
		args         args
		policy       string
		wantPolicies []*entity.Policy
		wantErr      bool
	}{
		{
			name: "Parse the policy successfully.",
			args: args{
				path: "testPolicy.yml",
			},
			policy: `
policies:
 - container:
    name: "test_container"
   communications:
    - executable: "test_exec"
      sockets:
       - protocol: "tcp"
         remote_host: "172.17.0.1"
         remote_port: 8080
`,
			wantPolicies: []*entity.Policy{{
				Container: &entity.Container{
					Name: "test_container",
				},
				Communications: []*entity.Communication{
					{
						Process: "test_exec",
						Sockets: []*entity.Socket{{
							Protocol:   "tcp",
							RemoteIP:   net.ParseIP("172.17.0.1"),
							RemotePort: 8080,
						}},
						ICMP: []*entity.ICMP{},
					},
				},
			}},
			wantErr: false,
		},
		{
			name: "Parse policy successfully even without remote_host",
			args: args{
				path: "testPolicy.yml",
			},
			policy: `
policies:
 - container:
    name: "test_container"
   communications:
    - executable: "test_exec"
      sockets:
       - protocol: "tcp"
         remote_port: 8080
`,
			wantPolicies: []*entity.Policy{{
				Container: &entity.Container{
					Name: "test_container",
				},
				Communications: []*entity.Communication{
					{
						Process: "test_exec",
						Sockets: []*entity.Socket{{
							Protocol:   "tcp",
							RemotePort: 8080,
						}},
						ICMP: []*entity.ICMP{},
					},
				},
			}},
			wantErr: false,
		},
		{
			name: "The container name is specified in remote_host and can be parse even if there are multiple IP addresses.",
			args: args{
				path: "testPolicy.yml",
			},
			policy: `
policies:
 - container:
    name: "test_container"
   communications:
    - executable: "test_exec"
      sockets:
       - protocol: "tcp"
         remote_host: "nginx_test"
`,
			wantPolicies: []*entity.Policy{{
				Container: &entity.Container{
					Name: "test_container",
				},
				Communications: []*entity.Communication{
					{
						Process: "test_exec",
						Sockets: []*entity.Socket{{
							Protocol: "tcp",
							RemoteIP: ipv4,
						}, {
							Protocol: "tcp",
							RemoteIP: ipv6,
						}},
						ICMP: []*entity.ICMP{},
					},
				},
			}},
			wantErr: false,
		},
		{
			name: "Return an error if the policy does not exist.",
			args: args{
				path: "testPolicy.yml",
			},
			policy: `
policies:
 - container:
    name: "test_container"
   communications:
    - executable: "test_exec"
      sockets:
       - protocol: "tcp"
         remote_host: "172.17.0.1"
         remote_port: 8080
		`,
			wantPolicies: nil,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := preparePolicy(t, tt.policy)
			assert := assert.New(t)

			gotPolicies, err := LoadPolicy(path, containers)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(tt.wantPolicies, gotPolicies)
		})
	}
}
