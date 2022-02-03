package cmd

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"furui/domain/entity"
	"furui/driver"
	"furui/infrastructure/docker"
	"furui/infrastructure/loader"
	containerRepo "furui/infrastructure/repository/impl/container"
	processRepo "furui/infrastructure/repository/impl/process"
	"furui/usecase/go/proc"
)

func TestMain(m *testing.M) {

	code := m.Run()

	os.Exit(code)
}

func TestEbpfRouter_HandleEvents(t *testing.T) {

	bindProg := readFile(t, "../usecase/ebpf/bind.c")
	connectProg := readFile(t, "../usecase/ebpf/connect.c")
	closeProg := readFile(t, "../usecase/ebpf/close.c")
	ingressProg := readFile(t, "../usecase/ebpf/ingress.c")
	egressProg := readFile(t, "../usecase/ebpf/egress.c")
	icmpIngressProg := readFile(t, "../usecase/ebpf/icmp_ingress.c")
	icmpEgressProg := readFile(t, "../usecase/ebpf/icmp_egress.c")

	type fields struct {
		runCmdArgs []string
	}
	tests := []struct {
		name             string
		fields           fields
		doRunInContainer bool
		wantErr          bool
		wantOutputs      []string
	}{
		{
			name: "Can successfully monitor the bind function call.",
			fields: fields{
				runCmdArgs: []string{"nc", "-lp", "8000"},
			},
			doRunInContainer: true,
			wantErr:          false,
			wantOutputs:      []string{"Comm: nc", "Protocol: TCPv4", "LocalPort: 8000"},
		},
		{
			name: "Can monitor tcp_connect normally.",
			fields: fields{
				runCmdArgs: []string{"curl", "-m", "1", "localhost"},
			},
			doRunInContainer: true,
			wantErr:          false,
			wantOutputs:      []string{"Comm: curl", "DestinationAddr: 127.0.0.1", "DestinationPort: 80", "Protocol: TCP"},
		},
		{
			name: "Can successfully monitor udp_send_skb.",
			fields: fields{
				runCmdArgs: []string{"../tools/sendUDP4Packet/main"},
			},
			doRunInContainer: true,
			wantErr:          false,
			wantOutputs:      []string{"Comm: main", "DestinationAddr: 127.0.0.1", "DestinationPort: 8888", "Protocol: UDP"},
		},
		{
			name: "Can monitor ingress communication normally.",
			fields: fields{
				runCmdArgs: []string{"curl", "-m", "1", "192.168.4.2"},
			},
			doRunInContainer: false,
			wantErr:          false,
			wantOutputs:      []string{"Protocol: TCP", "DestinationPort: 80"},
		},
		{
			name: "Can monitor ICMPIngress communication normally.",
			fields: fields{
				runCmdArgs: []string{"ping", "-c", "1", "192.168.4.2"},
			},
			doRunInContainer: true,
			wantErr:          false,
			wantOutputs:      []string{"SourceAddr: 192.168.0.1", "DestinationAddr: 192.168.4.2"},
		}, {
			name: "Can monitor process termination events normally.",
			fields: fields{
				runCmdArgs: []string{"curl", "-m", "1", "127.0.0.1"},
			},
			doRunInContainer: true,
			wantErr:          false,
			wantOutputs:      []string{"a termination of the process that was communicating detected"},
		},
	}

	dockerInfra := docker.New(driver.DockerCLI())

	containers := entity.NewContainers(nil)

	err := dockerInfra.AddRunningContainersInspect(containers)
	if err != nil {
		t.Fatalf("failed to get containers information: %+v", err)
		return
	}

	processes := proc.GetProcesses(containers)

	l := loader.NewLoader(bindProg, connectProg, closeProg, ingressProg, egressProg, icmpIngressProg, icmpEgressProg)
	bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule, err := l.LoadModules()
	if err != nil {
		t.Fatalf("failed to load modules: %+v", err)
	}

	// Store the container ID in Map so that it can be retrieved from the IP address.
	containerRepository := containerRepo.NewContainerRepository(ingressModule)
	if err = containerRepository.SaveIDWithIPs(containers); err != nil {
		t.Fatalf("failed to container's ip with id: %+v", err)
		return
	}

	processRepository := processRepo.NewProcessRepository(bindModule)
	if err = processRepository.SaveProcesses(processes); err != nil {
		t.Fatalf("failed to store processes: %+v", err)
		return
	}

	t.Cleanup(func() {
		err = l.UnLoadModules(bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule)
		if err != nil {
			t.Errorf("failed to unload modules: %+v", err)
			return
		}
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			r := &EbpfRouter{
				bindModule:        bindModule,
				connectModule:     connectModule,
				closeModule:       closeModule,
				ingressModule:     ingressModule,
				egressModule:      egressModule,
				icmpIngressModule: icmpIngressModule,
				icmpEgressModule:  icmpEgressModule,
			}
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			start := make(chan string, 1)

			go func() {
				// Stop until we start monitoring.
				<-start
				runAnotherNameSpace(t, tt.doRunInContainer, tt.fields.runCmdArgs...)
				// Issue an order to terminate the surveillance.
				// Wait a little while until the log is completely output.
				time.Sleep(time.Second * 2)
				sig <- syscall.SIGTERM
			}()

			gotOutput, err := extractLog(t, r.HandleEvents, sig, start, processRepository, processes)
			if (err != nil) != tt.wantErr {
				t.Errorf("EbpfRouter test error = %v, wantErr %v", err, tt.wantErr)
			}
			for _, wantOutput := range tt.wantOutputs {
				assert.Contains(t, gotOutput, wantOutput)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("HandleEvents() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
