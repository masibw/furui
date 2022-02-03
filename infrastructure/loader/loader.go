package loader

import (
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"furui/constant"
	"furui/pkg/file"
	"furui/pkg/nic"
	"furui/pkg/object"

	"golang.org/x/xerrors"

	bpf "github.com/iovisor/gobpf/bcc"
)

type Loader interface {
	LoadModules() (*bpf.Module, *bpf.Module, *bpf.Module, *bpf.Module, *bpf.Module, *bpf.Module, *bpf.Module, error)
	AttachProgsToQdisc() (*bpf.Module, *bpf.Module, *bpf.Module, *bpf.Module, error)
	UnLoadModules(*bpf.Module, *bpf.Module, *bpf.Module, *bpf.Module, *bpf.Module, *bpf.Module, *bpf.Module) error
	LoadBindProg() (*bpf.Module, error)
	LoadConnectProg() (*bpf.Module, error)
	LoadCloseProg() (*bpf.Module, error)
	LoadIngressProg() (*bpf.Module, error)
	LoadEgressProg() (*bpf.Module, error)
	LoadICMPIngressProg() (*bpf.Module, error)
	LoadICMPEgressProg() (*bpf.Module, error)
	UnLoadIngressProg() error
	UnLoadEgressProg() error
	DeleteQdisc(nicName string) error
}

type EbpfLoader struct {
	bindProg        []byte
	connectProg     []byte
	closeProg       []byte
	ingressProg     []byte
	egressProg      []byte
	icmpIngressProg []byte
	icmpEgressProg  []byte
}

func NewLoader(bindProg, connectProg, closeProg, ingressProg, egressProg, icmpIngressProg, icmpEgressProg []byte) Loader {
	return &EbpfLoader{
		bindProg:        bindProg,
		connectProg:     connectProg,
		closeProg:       closeProg,
		ingressProg:     ingressProg,
		egressProg:      egressProg,
		icmpIngressProg: icmpIngressProg,
		icmpEgressProg:  icmpEgressProg,
	}
}

func (l *EbpfLoader) LoadModules() (bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule *bpf.Module, err error) {
	bindModule, err = l.LoadBindProg()
	if err != nil {
		err = xerrors.Errorf("failed to LoadBindProg(): %+v", err)
		return
	}

	connectModule, err = l.LoadConnectProg()
	if err != nil {
		err = xerrors.Errorf("failed to LoadConnectProg(): %+v", err)
		return
	}

	closeModule, err = l.LoadCloseProg()
	if err != nil {
		err = xerrors.Errorf("failed to LoadCloseProg(): %+v", err)
		return
	}

	ingressModule, egressModule, icmpIngressModule, icmpEgressModule, err = l.AttachProgsToQdisc()
	if err != nil {
		err = xerrors.Errorf("failed to attach programs to qdisc: %w", err)
		return
	}
	return
}

func (l *EbpfLoader) AttachProgsToQdisc() (ingressModule, egressModule, icmpIngressModule, icmpEgressModule *bpf.Module, err error) {
	var nicNames []string
	nicNames, err = nic.GetNamesConnectedToContainers()
	if err != nil {
		err = xerrors.Errorf("failed to get nic names :%+v", err)
		return
	}

	// Create a clsact on veth that connects the container to docker0
	for _, nicName := range nicNames {
		err = l.CreateClsact(nicName)
		if err != nil {
			err = xerrors.Errorf("failed to create interface: %s, clsact: %+v", nicName, err)
			return
		}
	}

	ingressModule, err = l.LoadIngressProg()
	if err != nil {
		err = xerrors.Errorf("failed to LoadIngressProg(): %+v", err)
		return
	}

	egressModule, err = l.LoadEgressProg()
	if err != nil {
		err = xerrors.Errorf("failed to LoadEgressProg(): %+v", err)
		return
	}

	icmpIngressModule, err = l.LoadICMPIngressProg()
	if err != nil {
		err = xerrors.Errorf("failed to LoadIngressICMPProg(): %+v", err)
		return
	}

	icmpEgressModule, err = l.LoadICMPEgressProg()
	if err != nil {
		err = xerrors.Errorf("failed to LoadEgressICMPProg(): %+v", err)
		return
	}
	return
}

// UnLoadModules cleans up modules.
func (l *EbpfLoader) UnLoadModules(bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule *bpf.Module) (err error) {
	bindModule.Close()
	connectModule.Close()
	closeModule.Close()
	ingressModule.Close()
	egressModule.Close()
	icmpIngressModule.Close()
	icmpEgressModule.Close()

	err = l.UnLoadIngressProg()
	if err != nil {
		err = xerrors.Errorf("failed to UnLoadIngressProg(): %+v", err)
		return
	}

	err = l.UnLoadEgressProg()
	if err != nil {
		err = xerrors.Errorf("failed to UnLoadEgressProg(): %+v", err)
		return
	}

	err = l.UnLoadICMPIngressProg()
	if err != nil {
		err = xerrors.Errorf("failed to UnLoadICMPIngressProg(): %+v", err)
		return
	}

	err = l.UnLoadICMPEgressProg()
	if err != nil {
		err = xerrors.Errorf("failed to UnLoadICMPIngressProg(): %+v", err)
		return
	}

	var nicNames []string
	nicNames, err = nic.GetNamesConnectedToContainers()
	if err != nil {
		err = xerrors.Errorf("failed to get nic names :%w", err)
		return
	}

	for _, nicName := range nicNames {
		err = l.DeleteQdisc(nicName)
		if err != nil {
			err = xerrors.Errorf("failed to delete interface: %s, err: %w", nicName, err)
			return
		}
	}

	return
}

func (l *EbpfLoader) LoadBindProg() (m *bpf.Module, err error) {
	m = bpf.NewModule(string(l.bindProg), []string{})
	bindKprobe, err := m.LoadKprobe("trace_inet_bind")
	if err != nil {
		err = xerrors.Errorf("failed to load bind program to kprobe: %w", err)
		return
	}

	bind6Kprobe, err := m.LoadKprobe("trace_inet6_bind")
	if err != nil {
		err = xerrors.Errorf("failed to load bind program to kprobe: %w", err)
		return
	}

	if err = m.AttachKprobe("inet_bind", bindKprobe, -1); err != nil {
		err = xerrors.Errorf("failed to attach bind program to kprobe: %w", err)
		return
	}

	if err = m.AttachKprobe("inet6_bind", bind6Kprobe, -1); err != nil {
		err = xerrors.Errorf("failed to attach bind program to kprobe: %w", err)
		return
	}
	return
}

func (l *EbpfLoader) LoadConnectProg() (m *bpf.Module, err error) {
	m = bpf.NewModule(string(l.connectProg), []string{})
	connectTCPKprobe, err := m.LoadKprobe("trace_tcp_connect")
	if err != nil {
		err = xerrors.Errorf("failed to load connect tcp program to kprobe: %w", err)
		return
	}

	connectUDPKprobe, err := m.LoadKprobe("trace_udp_connect")
	if err != nil {
		err = xerrors.Errorf("failed to load connect udp program to kprobe: %w", err)
		return
	}

	connect6UDPKprobe, err := m.LoadKprobe("trace_udp6_connect")
	if err != nil {
		err = xerrors.Errorf("failed to load connect6 udp program to kprobe: %w", err)
		return
	}

	if err = m.AttachKprobe("tcp_connect", connectTCPKprobe, -1); err != nil {
		err = xerrors.Errorf("failed to attach connect tcp program to kprobe: %w", err)
		return
	}
	if err = m.AttachKprobe("udp_send_skb", connectUDPKprobe, -1); err != nil {
		err = xerrors.Errorf("failed to attach connect udp program to kprobe: %w", err)
		return
	}

	if err = m.AttachKprobe("udp_v6_send_skb", connect6UDPKprobe, -1); err != nil {
		err = xerrors.Errorf("failed to attach connect udp program to kprobe: %w", err)
		return
	}
	return
}

func (l *EbpfLoader) LoadCloseProg() (m *bpf.Module, err error) {
	m = bpf.NewModule(string(l.closeProg), []string{})
	return
}

func doesClsactExists(nicName string) (exist bool, err error) {
	out, err := exec.Command("tc", "qdisc", "show", "dev", nicName).CombinedOutput() // #nosec //TODO: I think it's safe to say that exec.Command doesn't interpret ;, &&, etc., but I'm not sure myself.
	if err != nil {
		err = xerrors.Errorf("failed to add egress filter: output: %s, err: %w", out, err)
		return
	}
	if strings.Contains(*(*string)(unsafe.Pointer(&out)), "qdisc clsact") {
		exist = true
	}
	return
}

func (l *EbpfLoader) CreateClsact(nicName string) (err error) {

	exist, err := doesClsactExists(nicName)
	if err != nil {
		err = xerrors.Errorf("failed to check doesClsactExists(): %w", err)
		return
	}
	// Create clsact only if it does not exist.
	if !exist {
		var output []byte
		output, err = exec.Command("tc", "qdisc", "add", "dev", nicName, "clsact").CombinedOutput() // #nosec //TODO: I think it's safe to say that exec.Command doesn't interpret ;, &&, etc., but I'm not sure myself.
		if err != nil {
			err = xerrors.Errorf("failed to add clsact qdisc output: %s, err: %w", output, err)
			return
		}
	}
	return
}

func (l *EbpfLoader) LoadIngressProg() (m *bpf.Module, err error) {
	m = bpf.NewModule(string(l.ingressProg), []string{})
	SchedCls := 3

	pinnedPath := fmt.Sprintf("/sys/fs/bpf/%s/globals/%s-%s", constant.NamespaceName, constant.ProgName, "ingress")
	if !file.Exists(pinnedPath) {
		if err != nil {
			err = xerrors.Errorf(": %w", err)
			return
		}
		var fn int
		fn, err = m.Load("ingress", SchedCls, 0, 0)
		if err != nil {
			err = xerrors.Errorf("failed to load ingress program: %w", err)
			return
		}

		err = object.Pin(fn, "ingress")
		if err != nil {
			err = xerrors.Errorf("failed to pin ingress object: %w", err)
			return
		}
	}

	// Attach a program between docker0 and each container
	nicNames, err := nic.GetNamesConnectedToContainers()
	if err != nil {
		err = xerrors.Errorf(": %w", err)
		return
	}

	for _, nicName := range nicNames {
		out, err2 := exec.Command("tc", "filter", "add", "dev", nicName, "egress", "bpf", "da", "object-pinned", pinnedPath).CombinedOutput() // #nosec //TODO: I think it's safe to say that exec.Command doesn't interpret ;, &&, etc., but I'm not sure myself.
		if err2 != nil {
			err = xerrors.Errorf("failed to add ingress filter: interface: %s, output: %s, err: %w", nicName, out, err2)
			return
		}
	}

	return
}

func (l *EbpfLoader) LoadEgressProg() (m *bpf.Module, err error) {
	m = bpf.NewModule(string(l.egressProg), []string{})
	SchedCls := 3

	pinnedPath := fmt.Sprintf("/sys/fs/bpf/%s/globals/%s-%s", constant.NamespaceName, constant.ProgName, "egress")
	if !file.Exists(pinnedPath) {
		var fn int
		fn, err = m.Load("egress", SchedCls, 0, 0)
		if err != nil {
			err = xerrors.Errorf("failed to load egress program: %w", err)
			return
		}

		err = object.Pin(fn, "egress")
		if err != nil {
			err = xerrors.Errorf("failed to pin egress object: %w", err)
			return
		}
	}
	// Attach a program between docker0 and each container
	nicNames, err := nic.GetNamesConnectedToContainers()
	if err != nil {
		err = xerrors.Errorf(": %w", err)
		return
	}

	for _, nicName := range nicNames {
		out, err2 := exec.Command("tc", "filter", "add", "dev", nicName, "ingress", "bpf", "da", "object-pinned", pinnedPath).CombinedOutput() // #nosec //TODO: I think it's safe to say that exec.Command doesn't interpret ;, &&, etc., but I'm not sure myself.
		if err2 != nil {
			err = xerrors.Errorf("failed to add ingress filter: interface: %s, output: %s, err: %w", nicName, out, err2)
			return
		}
	}

	return
}

func (l *EbpfLoader) LoadICMPIngressProg() (m *bpf.Module, err error) {
	m = bpf.NewModule(string(l.icmpIngressProg), []string{})
	SchedCls := 3

	pinnedPath := fmt.Sprintf("/sys/fs/bpf/%s/globals/%s-%s", constant.NamespaceName, constant.ProgName, "ICMP-ingress")
	if !file.Exists(pinnedPath) {
		var fn int
		fn, err = m.Load("ingress", SchedCls, 0, 0)
		if err != nil {
			err = xerrors.Errorf("failed to load icmp-ingress program: %w", err)
			return
		}

		err = object.Pin(fn, "ICMP-ingress")
		if err != nil {
			err = xerrors.Errorf("failed to pin ICMP-ingress object: %w", err)
			return
		}
	}
	// Attach a program between docker0 and each container
	nicNames, err := nic.GetNamesConnectedToContainers()
	if err != nil {
		err = xerrors.Errorf(": %w", err)
		return
	}

	for _, nicName := range nicNames {
		out, err2 := exec.Command("tc", "filter", "add", "dev", nicName, "egress", "bpf", "da", "object-pinned", pinnedPath).CombinedOutput() // #nosec //TODO: I think it's safe to say that exec.Command doesn't interpret ;, &&, etc., but I'm not sure myself.
		if err2 != nil {
			err = xerrors.Errorf("failed to add ingress filter: interface: %s, output: %s, err: %w", nicName, out, err2)
			return
		}
	}

	return
}

func (l *EbpfLoader) LoadICMPEgressProg() (m *bpf.Module, err error) {
	m = bpf.NewModule(string(l.icmpEgressProg), []string{})
	SchedCls := 3
	pinnedPath := fmt.Sprintf("/sys/fs/bpf/%s/globals/%s-%s", constant.NamespaceName, constant.ProgName, "ICMP-egress")

	if !file.Exists(pinnedPath) {
		var fn int
		fn, err = m.Load("egress", SchedCls, 0, 0)
		if err != nil {
			err = xerrors.Errorf("failed to load ICMPegress program: %w", err)
			return
		}

		err = object.Pin(fn, "ICMP-egress")
		if err != nil {
			err = xerrors.Errorf("failed to pin ICMPegress object: %w", err)
			return
		}

	}
	// Attach a program between docker0 and each container
	nicNames, err := nic.GetNamesConnectedToContainers()
	if err != nil {
		err = xerrors.Errorf(": %w", err)
		return
	}

	for _, nicName := range nicNames {
		out, err2 := exec.Command("tc", "filter", "add", "dev", nicName, "ingress", "bpf", "da", "object-pinned", pinnedPath).CombinedOutput() // #nosec //TODO: I think it's safe to say that exec.Command doesn't interpret ;, &&, etc., but I'm not sure myself.
		if err2 != nil {
			err = xerrors.Errorf("failed to add ICMPegress filter: interface: %s, output: %s, err: %w", nicName, out, err2)
			return
		}
	}

	return

}

func (l *EbpfLoader) UnLoadIngressProg() (err error) {
	err = object.Unlink("ingress")
	if err != nil {
		err = xerrors.Errorf("failed to unlink ingress program: %w", err)
		return
	}
	return
}

func (l *EbpfLoader) UnLoadICMPIngressProg() (err error) {
	err = object.Unlink("ICMP-ingress")
	if err != nil {
		err = xerrors.Errorf("failed to unlink ICMP-ingress program: %w", err)
		return
	}
	return
}

func (l *EbpfLoader) UnLoadEgressProg() (err error) {
	err = object.Unlink("egress")
	if err != nil {
		err = xerrors.Errorf("failed to unlink egress program: %w", err)
		return
	}
	return
}

func (l *EbpfLoader) UnLoadICMPEgressProg() (err error) {
	err = object.Unlink("ICMP-egress")
	if err != nil {
		err = xerrors.Errorf("failed to unlink ICMP-egress program: %w", err)
		return
	}
	return
}

func (l *EbpfLoader) DeleteQdisc(nicName string) (err error) {
	_, err = exec.Command("tc", "qdisc", "del", "dev", nicName, "clsact").CombinedOutput() // #nosec //TODO: I think it's safe to say that exec.Command doesn't interpret ;, &&, etc., but I'm not sure myself.
	if err != nil {
		err = xerrors.Errorf("failed to del clsact qdisc: %w", err)
		return
	}
	return
}
