package policy

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/stretchr/testify/assert"

	"furui/constant"
	"furui/domain/entity"
	"furui/infrastructure/loader"
	"furui/pkg/convert"
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

func TestPolicyRepository_Save(t *testing.T) {

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

	r := &Repository{
		Module: ingressModule,
		ICMP:   icmpIngressModule,
	}
	policyList := bpf.NewTable(ingressModule.TableId("policy_list"), ingressModule)
	ICMPPolicyList := bpf.NewTable(icmpIngressModule.TableId("icmp_policy_list"), icmpIngressModule)
	type args struct {
		EPolicies []*entity.Policy
	}

	tests := []struct {
		name      string
		args      args
		wantErr   bool
		key       Key
		wantValue *Value
	}{
		{
			name: "Save policy",
			args: args{
				EPolicies: []*entity.Policy{
					{
						Container: &entity.Container{
							ID: "container_id",
						},
						Communications: []*entity.Communication{
							{
								Process: "nginx",
								Sockets: []*entity.Socket{
									{
										Protocol:   "tcp",
										LocalPort:  uint16(80),
										RemoteIP:   net.ParseIP("127.0.0.1"),
										RemotePort: uint16(30000),
									},
								},
							},
						},
					},
				},
			},
			wantErr: false,
			key: Key{
				ContainerID: [constant.ContainerIDCap]byte{99, 111, 110, 116, 97, 105, 110, 101, 114, 95, 105, 100, 0, 0, 0, 0},
				Executable:  [constant.TaskCommLen]byte{110, 103, 105, 110, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				RemoteIP:    binary.LittleEndian.Uint32(net.ParseIP("127.0.0.1")[12:16]),
				LocalPort:   uint16(80),
				RemotePort:  uint16(30000),
				Protocol:    convert.StringToProto("tcp"),
			},

			wantValue: &Value{
				Executable: [constant.TaskCommLen]byte{110, 103, 105, 110, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				RemoteIP:   binary.LittleEndian.Uint32(net.ParseIP("127.0.0.1")[12:16]),
				LocalPort:  uint16(80),
				RemotePort: uint16(30000),
				Protocol:   convert.StringToProto("tcp"),
			},
		},
	}

	icmpTests := []struct {
		name      string
		args      args
		wantErr   bool
		key       IcmpKey
		wantValue *IcmpValue
	}{
		{
			name: "Save icmp_policy",
			args: args{
				EPolicies: []*entity.Policy{
					{
						Container: &entity.Container{
							ID: "container_id",
						},
						Communications: []*entity.Communication{
							{
								Process: "nginx",
								ICMP: []*entity.ICMP{
									{
										Version:  4,
										Type:     8,
										Code:     0,
										RemoteIP: net.ParseIP("172.17.0.2"),
									},
								},
							},
						},
					},
				},
			},
			wantErr: false,
			key: IcmpKey{
				ContainerID: [constant.ContainerIDCap]byte{99, 111, 110, 116, 97, 105, 110, 101, 114, 95, 105, 100, 0, 0, 0, 0},
				Version:     uint8(4),
				Type:        uint8(8),
				Code:        uint8(0),
				RemoteIP:    binary.LittleEndian.Uint32(net.ParseIP("172.17.0.2")[12:16]),
			},

			wantValue: &IcmpValue{
				Version:  uint8(4),
				Type:     uint8(8),
				Code:     uint8(0),
				RemoteIP: binary.LittleEndian.Uint32(net.ParseIP("172.17.0.2")[12:16]),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := r.Save(tt.args.EPolicies); (err != nil) != tt.wantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.wantErr)
			}
			key := tt.key
			val, err := policyList.GetP(unsafe.Pointer(&key))
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantValue, (*Value)(val))

		})
	}

	for _, tt := range icmpTests {
		t.Run(tt.name, func(t *testing.T) {
			if err := r.Save(tt.args.EPolicies); (err != nil) != tt.wantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.wantErr)
			}
			icmpKey := tt.key
			val, err := ICMPPolicyList.GetP(unsafe.Pointer(&icmpKey))
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.wantValue, (*IcmpValue)(val))

		})
	}
}
