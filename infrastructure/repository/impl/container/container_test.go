package container

import (
	"encoding/binary"
	"net"
	"os"
	"strings"
	"testing"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/stretchr/testify/assert"

	"furui/constant"
	"furui/domain/entity"
	"furui/infrastructure/loader"
)

// readFile opens a file at the specified path and returns []bytes
func readFile(t *testing.T, path string) (p []byte) {
	t.Helper()
	var err error
	p, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to open file path: %s, err: %s", path, err)
		return nil
	}
	return
}

func TestContainerRepository_SaveIDWithIPs(t *testing.T) {

	bindProg := readFile(t, "../../../../usecase/ebpf/bind.c")
	connectProg := readFile(t, "../../../../usecase/ebpf/connect.c")
	closeProg := readFile(t, "../../../../usecase/ebpf/close.c")
	ingressProg := readFile(t, "../../../../usecase/ebpf/ingress.c")
	egressProg := readFile(t, "../../../../usecase/ebpf/egress.c")
	icmpIngressProg := readFile(t, "../../../../usecase/ebpf/icmp_ingress.c")
	icmpEgressProg := readFile(t, "../../../../usecase/ebpf/icmp_egress.c")

	l := loader.NewLoader(bindProg, connectProg, closeProg, ingressProg, egressProg, icmpIngressProg, icmpEgressProg)
	bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule, err := l.LoadModules()
	if err != nil {
		t.Fatalf("failed to load modules: %+v", err)
	}

	t.Cleanup(func() {
		err = l.UnLoadModules(bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule)
		if err != nil {
			t.Errorf("failed to unload modules: %+v", err)
			return
		}
	})

	type args struct {
		containers *entity.Containers
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		key       Key
		wantValue *Value
	}{
		{
			name: "Save container's IP And ID",
			args: args{
				containers: entity.NewContainers(
					[]*entity.Container{
						{
							ID: "container_id",
							IPAddresses: []net.IP{
								net.ParseIP("172.0.0.1"),
								net.ParseIP("172.0.0.2"),
							},
							Name: "container_name",
						},
					},
				),
			},
			wantErr: false,
			wantValue: &Value{
				ContainerID: [constant.ContainerIDCap]byte{99, 111, 110, 116, 97, 105, 110, 101, 114, 95, 105, 100},
			},
		},
	}
	r := &Repository{
		Module: ingressModule,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if err := r.SaveIDWithIPs(tt.args.containers); (err != nil) != tt.wantErr {
				t.Errorf("SaveIDWithIPs() error = %v, wantErr %v", err, tt.wantErr)
			}

			idFromIPs := bpf.NewTable(ingressModule.TableId("container_id_from_ips"), ingressModule)
			for _, container := range tt.args.containers.List() {
				for _, ip := range container.IPAddresses {
					// Assign to a new variable since pointers are used repeatedly in for range
					k := Key{}

					if strings.Count(ip.String(), ":") < 2 {
						k.ip = binary.LittleEndian.Uint32(ip[12:16])
					} else if strings.Count(ip.String(), ":") >= 2 {
						copy(k.ipv6[:], ip)
					}
					val, err := idFromIPs.GetP(unsafe.Pointer(&k))
					if err != nil {
						t.Fatal(err)
					}
					assert.Equal(t, tt.wantValue, (*Value)(val))
				}
			}
		})
	}
}
