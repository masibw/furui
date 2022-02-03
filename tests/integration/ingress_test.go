package integration

import (
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"

	"furui/domain/entity"
)

// TestIngress assumes that Nginx is mapped in docker to port 80 of the host with the name nginx_test
func TestIngress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode.")
	}

	type args struct {
		EPolicies        []*entity.Policy
		runCmdArgs       []string
		doRunInContainer bool
	}

	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantOutputs []string
	}{
		{
			name: "Allowed incoming packets can be communicated.",
			args: args{
				EPolicies: []*entity.Policy{
					{
						Container: &entity.Container{
							Name: "nginx_test",
						},
						Communications: []*entity.Communication{
							{
								Process: "nginx",
								Sockets: []*entity.Socket{
									{
										Protocol:  "tcp",
										LocalPort: uint16(80),
									},
								},
							},
						},
					},
				},
				runCmdArgs:       []string{"curl", "-m", "1", "192.168.4.2"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"Welcome to nginx!"},
		},
		{
			name: "Even if only RemoteIP is specified in policy, allowed incoming packets can be communicated.",
			args: args{
				EPolicies: []*entity.Policy{
					{
						Container: &entity.Container{
							Name: "nginx_test",
						},
						Communications: []*entity.Communication{
							{
								Process: "nginx",
								Sockets: []*entity.Socket{
									{
										RemoteIP: net.ParseIP("192.168.4.3"),
									},
								},
							},
						},
					},
					{
						Container: &entity.Container{
							Name: "httpd_test",
						},
						Communications: []*entity.Communication{
							{
								Process: "curl",
								Sockets: []*entity.Socket{},
							},
						},
					},
				},
				runCmdArgs:       []string{"docker", "exec", "httpd_test", "curl", "-m", "1", "192.168.4.2"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"Welcome to nginx!"},
		},
		{
			name: "Unauthorized incoming packets can be denied.",
			args: args{
				EPolicies:        nil,
				runCmdArgs:       []string{"curl", "-m", "1", "192.168.4.2"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"timed out"},
		},
		{
			name: "Allowed IPv6 inbound packets can be communicated",
			args: args{
				EPolicies: []*entity.Policy{
					{
						Container: &entity.Container{
							Name: "nginx_test",
						},
						Communications: []*entity.Communication{
							{
								Process: "nginx",
								Sockets: []*entity.Socket{
									{
										Protocol:  "tcp",
										LocalPort: uint16(80),
										RemoteIP:  net.ParseIP("fd00::2:3"),
									},
								},
							},
						},
					},
					{
						Container: &entity.Container{
							Name: "httpd_test",
						},
						Communications: []*entity.Communication{
							{
								Process: "curl",
								Sockets: []*entity.Socket{},
							},
						},
					},
				},
				runCmdArgs:       []string{"docker", "exec", "httpd_test", "curl", "-m", "1", "-g", "http://[fd00::2:2]"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"Welcome to nginx!"},
		},
		{
			name: "Can receive and communicate with ICMP packets that are allowed.",
			args: args{
				EPolicies: []*entity.Policy{
					{
						Container: &entity.Container{
							Name: "nginx_test",
						},
						Communications: []*entity.Communication{
							{
								ICMP: []*entity.ICMP{
									{
										Version: 4,
										Type:    8,
										Code:    0,
									},
								},
							},
						},
					},
				},
				runCmdArgs:       []string{"ping", "-c", "1", "-w", "1", "192.168.4.2"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"0% packet loss"},
		},
		{
			name: "Receive and deny unauthorized ICMP packets.",
			args: args{
				EPolicies:        nil,
				runCmdArgs:       []string{"ping", "-c", "1", "-w", "1", "172.17.0.2"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"0 received"},
		},
		{
			name: "Can receive and communicate with ICMPv6 packets that are allowed.",
			args: args{
				EPolicies: []*entity.Policy{
					{
						Container: &entity.Container{
							Name: "nginx_test",
						},
						Communications: []*entity.Communication{
							{
								ICMP: []*entity.ICMP{
									{
										Version: 6,
										Type:    128,
									},
								},
							},
						},
					},
				},
				runCmdArgs:       []string{"ping", "-c", "1", "-w", "1", "fd00::2:2"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"0% packet loss"},
		},
		{
			name: "Receive and reject ICMPv6 packets that are not allowed.",
			args: args{
				EPolicies:        nil,
				runCmdArgs:       []string{"ping", "-c", "1", "-w", "1", "fd00::2:2"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"0 received"},
		},
	}

	l, r, policyRepository, containerRepository, processRepository, dockerInfra, containers, sig, start := Prepare(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotRunOutput string
			go func() {
				// Stop until we start monitoring.
				<-start
				gotRunOutput = runCmd(t, tt.args.doRunInContainer, tt.args.runCmdArgs...)
				// Issue an order to terminate the surveillance.
				sig <- syscall.SIGTERM
			}()
			runner := &RouterRunner{
				loader:              l,
				router:              r,
				policyRepository:    policyRepository,
				containerRepository: containerRepository,
				processRepository:   processRepository,
				dockerInfra:         dockerInfra,
				containers:          containers,
				policies:            tt.args.EPolicies,
			}
			_, err := extractLog(t, runner, sig, start)

			if (err != nil) != tt.wantErr {
				t.Errorf("HandleEvents() error = %v, wantErr %v", err, tt.wantErr)
			}
			for _, wantOutput := range tt.wantOutputs {
				assert.Contains(t, gotRunOutput, wantOutput)
			}

			t.Cleanup(func() {
				ClearPolicy(t, r, tt.args.EPolicies)
			})
		})
	}
}
