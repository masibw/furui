package integration

import (
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"

	"furui/domain/entity"
)

func TestEgress(t *testing.T) {
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
			name: "Allowed outgoing packets can be communicated.",
			args: args{
				EPolicies: []*entity.Policy{
					{
						Container: &entity.Container{
							Name: "nginx_test",
						},
						Communications: []*entity.Communication{
							{
								Process: "curl",
								Sockets: []*entity.Socket{
									{
										Protocol: "tcp",
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
								Process: "httpd",
								Sockets: []*entity.Socket{},
							},
						},
					},
				},
				runCmdArgs:       []string{"docker", "exec", "nginx_test", "curl", "-m", "1", "192.168.4.3"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"It works!"},
		},
		{
			name: "Even if only RemoteIP is specified in policy, allowed outgoing packets can be communicated.",
			args: args{
				EPolicies: []*entity.Policy{
					{
						Container: &entity.Container{
							Name: "nginx_test",
						},
						Communications: []*entity.Communication{
							{
								Process: "curl",
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
								Process: "httpd",
								Sockets: []*entity.Socket{},
							},
						},
					},
				},
				runCmdArgs:       []string{"docker", "exec", "nginx_test", "curl", "-m", "1", "192.168.4.3"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"It works!"},
		},
		{
			name: "Unauthorized outgoing packets can be denied.",
			args: args{
				EPolicies:        nil,
				runCmdArgs:       []string{"docker", "exec", "nginx_test", "curl", "-m", "1", "192.168.4.3"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"timed out"},
		},
		{
			name: "Permitted IPv6 outgoing packets can be communicated.",
			args: args{
				EPolicies: []*entity.Policy{
					{
						Container: &entity.Container{
							Name: "nginx_test",
						},
						Communications: []*entity.Communication{
							{
								Process: "curl",
								Sockets: []*entity.Socket{
									{
										Protocol: "tcp",
										RemoteIP: net.ParseIP("fd00::2:3"),
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
								Process: "httpd",
								Sockets: []*entity.Socket{},
							},
						},
					},
				},
				// Access nginx on host 80 and port forwarded nginx_test by accessing docker0
				runCmdArgs:       []string{"docker", "exec", "nginx_test", "curl", "-m", "1", "-g", "http://[fd00::2:3]"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"It works!"},
		},
		{
			name: "Can send and communicate ICMP packets that are allowed.",
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
									{
										Version: 4,
										Type:    0,
										Code:    0,
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
								ICMP: []*entity.ICMP{
									{
										Version: 4,
										Type:    8,
										Code:    0,
									},
									{
										Version: 4,
										Type:    0,
										Code:    0,
									},
								},
							},
						},
					},
				},
				runCmdArgs:       []string{"docker", "exec", "nginx_test", "ping", "-c", "1", "-w", "1", "192.168.4.2"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"0% packet loss"},
		},
		{
			name: "Send and deny unauthorized ICMP packets.",
			args: args{
				EPolicies:        nil,
				runCmdArgs:       []string{"docker", "exec", "nginx_test", "ping", "-c", "1", "-w", "1", "192.168.4.3"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"100% packet loss"},
		},
		{
			name: "Send ICMPv6 packets that are allowed and can be communicated.",
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
									{
										Version: 6,
										Type:    129,
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
								ICMP: []*entity.ICMP{
									{
										Version: 6,
										Type:    128,
									},
									{
										Version: 6,
										Type:    129,
									},
								},
							},
						},
					},
				},
				runCmdArgs:       []string{"docker", "exec", "nginx_test", "ping", "-c", "1", "-w", "1", "fd00::2:3"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"0% packet loss"},
		},
		{
			name: "Send and deny unauthorized ICMPv6 packets.",
			args: args{
				EPolicies:        nil,
				runCmdArgs:       []string{"docker", "exec", "nginx_test", "ping", "-c", "1", "-w", "1", "fd00::2:3"},
				doRunInContainer: false,
			},
			wantErr:     false,
			wantOutputs: []string{"100% packet loss"},
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
				t.Errorf("Egress integration test error = %v, wantErr %v", err, tt.wantErr)
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
