package cmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/pkg/tracepipe"
	"golang.org/x/xerrors"

	"furui/constant"
	"furui/domain/entity"
	"furui/domain/valueobject"
	"furui/infrastructure/log"
	processRepo "furui/infrastructure/repository/interface/process"
	"furui/pkg/convert"
)

type Router interface {
	HandleEvents(start chan string, processRepository processRepo.Repository, processes []*entity.Process) (func(), error)
	GetIngressModule() *bpf.Module
	GetICMPIngressModule() *bpf.Module
	PrepareChannels() (ChannelAggregator, PerfMapAggregator, error)
}

type ChannelAggregator struct {
	bindChan         chan []byte
	connectChan      chan []byte
	connect6Chan     chan []byte
	closeChan        chan []byte
	ingressChan      chan []byte
	ingress6Chan     chan []byte
	egressChan       chan []byte
	egress6Chan      chan []byte
	icmpIngressChan  chan []byte
	icmpIngress6Chan chan []byte
	icmpEgressChan   chan []byte
	icmpEgress6Chan  chan []byte
}

type PerfMapAggregator struct {
	bindPerfMap         *bpf.PerfMap
	connectPerfMap      *bpf.PerfMap
	connect6PerfMap     *bpf.PerfMap
	closePerfMap        *bpf.PerfMap
	ingressPerfMap      *bpf.PerfMap
	ingress6PerfMap     *bpf.PerfMap
	egressPerfMap       *bpf.PerfMap
	egress6PerfMap      *bpf.PerfMap
	icmpIngressPerfMap  *bpf.PerfMap
	icmpIngress6PerfMap *bpf.PerfMap
	icmpEgressPerfMap   *bpf.PerfMap
	icmpEgress6PerfMap  *bpf.PerfMap
}

type EbpfRouter struct {
	bindModule        *bpf.Module
	connectModule     *bpf.Module
	closeModule       *bpf.Module
	ingressModule     *bpf.Module
	egressModule      *bpf.Module
	icmpIngressModule *bpf.Module
	icmpEgressModule  *bpf.Module
}

func NewRouter(bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule *bpf.Module) Router {
	return &EbpfRouter{
		bindModule:        bindModule,
		connectModule:     connectModule,
		closeModule:       closeModule,
		ingressModule:     ingressModule,
		egressModule:      egressModule,
		icmpIngressModule: icmpIngressModule,
		icmpEgressModule:  icmpEgressModule,
	}
}

func (r *EbpfRouter) GetIngressModule() *bpf.Module {
	return r.ingressModule
}

func (r *EbpfRouter) GetICMPIngressModule() *bpf.Module {
	return r.icmpIngressModule
}

func (r *EbpfRouter) PrepareChannels() (channelAggregator ChannelAggregator, perfMapAggregator PerfMapAggregator, err error) {
	bindEventsTable := bpf.NewTable(r.bindModule.TableId("bind_events"), r.bindModule)
	channelAggregator.bindChan = make(chan []byte, 1000)

	perfMapAggregator.bindPerfMap, err = bpf.InitPerfMap(bindEventsTable, channelAggregator.bindChan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init bind perf map: %w", err)
		return
	}

	connectEventsTable := bpf.NewTable(r.connectModule.TableId("connect_events"), r.connectModule)
	channelAggregator.connectChan = make(chan []byte, 1000)

	perfMapAggregator.connectPerfMap, err = bpf.InitPerfMap(connectEventsTable, channelAggregator.connectChan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init connect perf map: %w", err)
		return
	}

	connect6EventsTable := bpf.NewTable(r.connectModule.TableId("connect6_events"), r.connectModule)
	channelAggregator.connect6Chan = make(chan []byte, 1000)

	perfMapAggregator.connect6PerfMap, err = bpf.InitPerfMap(connect6EventsTable, channelAggregator.connect6Chan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init connect6 perf map: %w", err)
		return
	}

	closeEventsTable := bpf.NewTable(r.closeModule.TableId("close_events"), r.closeModule)
	channelAggregator.closeChan = make(chan []byte, 1000)

	perfMapAggregator.closePerfMap, err = bpf.InitPerfMap(closeEventsTable, channelAggregator.closeChan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init close perf map: %w", err)
		return
	}

	ingressEventsTable := bpf.NewTable(r.ingressModule.TableId("ingress_events"), r.ingressModule)
	channelAggregator.ingressChan = make(chan []byte, 1000)

	perfMapAggregator.ingressPerfMap, err = bpf.InitPerfMap(ingressEventsTable, channelAggregator.ingressChan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init ingress perf map: %w", err)
		return
	}

	ingress6EventsTable := bpf.NewTable(r.ingressModule.TableId("ingress6_events"), r.ingressModule)
	channelAggregator.ingress6Chan = make(chan []byte, 1000)

	perfMapAggregator.ingress6PerfMap, err = bpf.InitPerfMap(ingress6EventsTable, channelAggregator.ingress6Chan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init ingress6 perf map: %w", err)
		return
	}

	egressEventsTable := bpf.NewTable(r.egressModule.TableId("egress_events"), r.egressModule)
	channelAggregator.egressChan = make(chan []byte, 1000)

	perfMapAggregator.egressPerfMap, err = bpf.InitPerfMap(egressEventsTable, channelAggregator.egressChan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init egress perf map: %w", err)
		return
	}

	egress6EventsTable := bpf.NewTable(r.egressModule.TableId("egress6_events"), r.egressModule)
	channelAggregator.egress6Chan = make(chan []byte, 1000)

	perfMapAggregator.egress6PerfMap, err = bpf.InitPerfMap(egress6EventsTable, channelAggregator.egress6Chan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init egress6 perf map: %w", err)
		return
	}

	icmpIngressTable := bpf.NewTable(r.icmpIngressModule.TableId("icmp_ingress"), r.icmpIngressModule)
	channelAggregator.icmpIngressChan = make(chan []byte, 1000)

	perfMapAggregator.icmpIngressPerfMap, err = bpf.InitPerfMap(icmpIngressTable, channelAggregator.icmpIngressChan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init icmp perf map: %w", err)
		return
	}

	icmpIngress6Table := bpf.NewTable(r.icmpIngressModule.TableId("icmp_ingress6"), r.icmpIngressModule)
	channelAggregator.icmpIngress6Chan = make(chan []byte, 1000)

	perfMapAggregator.icmpIngress6PerfMap, err = bpf.InitPerfMap(icmpIngress6Table, channelAggregator.icmpIngress6Chan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init icmp perf map: %w", err)
		return
	}

	icmpEgressTable := bpf.NewTable(r.icmpEgressModule.TableId("icmp_egress"), r.icmpEgressModule)
	channelAggregator.icmpEgressChan = make(chan []byte, 1000)

	perfMapAggregator.icmpEgressPerfMap, err = bpf.InitPerfMap(icmpEgressTable, channelAggregator.icmpEgressChan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init icmp perf map: %w", err)
		return
	}

	icmpEgress6Table := bpf.NewTable(r.icmpEgressModule.TableId("icmp_egress6"), r.icmpEgressModule)
	channelAggregator.icmpEgress6Chan = make(chan []byte, 1000)

	perfMapAggregator.icmpEgress6PerfMap, err = bpf.InitPerfMap(icmpEgress6Table, channelAggregator.icmpEgress6Chan, nil)
	if err != nil {
		err = xerrors.Errorf("failed to init icmp perf map: %w", err)
		return
	}
	return
}

// HandleEvents handles the data obtained by eBPF, and if the start channel is passed, sends "start" at the beginning of the monitoring.
func (r *EbpfRouter) HandleEvents(start chan string, processRepository processRepo.Repository, processes []*entity.Process) (clean func(), err error) {
	cA, pA, err := r.PrepareChannels()
	if err != nil {
		err = xerrors.Errorf("failed to prepare channels: %w", err)
		return
	}

	tp, err := tracepipe.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	defer tp.Close()

	pidPorts := make(map[uint32][]*entity.Process)

	for _, process := range processes {
		pidPorts[process.Pid] = append(pidPorts[process.Pid], process)
	}

	channel2, errorChannel := tp.Channel()
	go func() {
		log.Logger.Infof("start watching")
		for { //nolint:gosimple
			select {
			case data := <-cA.bindChan:
				var event valueobject.BindEvent
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}

				pidPorts[event.Pid] = append(pidPorts[event.Pid], &entity.Process{
					ContainerID: string(event.ContainerID[:]),
					Protocol:    event.Proto,
					Port:        event.Lport,
				})

				log.Logger.Infof("a process start to listen. container_id: %s, Pid: %d, Comm: %s, Protocol: %s, LocalPort: %d", bytes.Trim(event.ContainerID[:], "\x00"), event.Pid, bytes.Trim(event.Comm[:], "\x00"), convert.ProtoToString(event.Proto)+convert.IPVersionToString(event.Family), event.Lport)
			case data := <-cA.connectChan:
				var event valueobject.ConnectEvent
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}

				pidPorts[event.Pid] = append(pidPorts[event.Pid], &entity.Process{
					ContainerID: string(event.ContainerID[:]),
					Protocol:    event.Proto,
					Port:        event.SPort,
				})

				log.Logger.Infof("a process start to connect. container_id: %s, Pid: %d, Comm: %s, Protocol: %s, SourceAddr: %s, SourcePort: %d, DestinationAddr: %s, DestinationPort: %d", bytes.Trim(event.ContainerID[:], "\x00"), event.Pid, bytes.Trim(event.Comm[:], "\x00"), convert.ProtoToString(event.Proto)+convert.IPVersionToString(event.Family), convert.Ntoa(event.SAddr), event.SPort, convert.Ntoa(event.DAddr), event.DPort)
			case data := <-cA.connect6Chan:
				var event valueobject.Connect6Event
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}
				log.Logger.Infof("a process start to connect. container_id: %s, Pid: %d, Comm: %s, Protocol: %s, SourceAddr: %s, SourcePort: %d, DestinationAddr: %s, DestinationPort: %d", bytes.Trim(event.ContainerID[:], "\x00"), event.Pid, bytes.Trim(event.Comm[:], "\x00"), convert.ProtoToString(event.Proto)+convert.IPVersionToString(event.Family), net.IP(event.SAddr[:]), event.SPort, net.IP(event.DAddr[:]), event.DPort)
			case data := <-cA.closeChan:
				var pid uint32
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &pid)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}

				if savedProcesses, exist := pidPorts[pid]; exist {
					for _, process := range savedProcesses {
						log.Logger.Debugf("process: %+v", process)
						err = processRepository.DeleteProcess(process)
						if err != nil {
							// Since two pidPorts are stored in TCPv4 and TCPv6, it is highly likely that one will fail.
							// It seems more costly to check for duplicates, so let them fail straightforwardly.
							log.Logger.Warnf("failed to delete process: %+v\n", err)
							continue
						}
					}
					log.Logger.Infof("a termination of the process that was communicating detected. Pid: %d", pid)
				}

			case data := <-cA.ingressChan:
				var event valueobject.IngressEvent
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}

				log.Logger.Infof("a ingress packet detected. action: %s, comm: %s, Protocol: %s, SourceAddr: %s, SourcePort: %d, DestinationAddr: %s, DestinationPort: %d", convert.ActionToString(event.Action), bytes.Trim(event.Comm[:], "\x00"), convert.ProtoToString(event.Proto), convert.Ntoa(event.SAddr), event.SPort, convert.Ntoa(event.DAddr), event.DPort)
			case data := <-cA.ingress6Chan:
				var event valueobject.Ingress6Event
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}
				log.Logger.Infof("a ingress packet detected. action: %s, comm: %s, Protocol: %s, SourceAddr: %s, SourcePort: %d, DestinationAddr: %s, DestinationPort: %d", convert.ActionToString(event.Action), bytes.Trim(event.Comm[:], "\x00"), convert.ProtoToString(event.Proto), net.IP(event.SAddr[:]), event.SPort, net.IP(event.DAddr[:]), event.DPort)
			case data := <-cA.egressChan:
				var event valueobject.EgressEvent
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}

				log.Logger.Infof("a egress packet detected. action: %s, comm: %s, Protocol: %s, SourceAddr: %s, SourcePort: %d, DestinationAddr: %s, DestinationPort: %d", convert.ActionToString(event.Action), bytes.Trim(event.Comm[:], "\x00"), convert.ProtoToString(event.Proto), convert.Ntoa(event.SAddr), event.SPort, convert.Ntoa(event.DAddr), event.DPort)
			case data := <-cA.egress6Chan:
				var event valueobject.Egress6Event
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}

				log.Logger.Infof("a egress packet detected. action: %s, comm: %s, Protocol: %s, SourceAddr: %s, SourcePort: %d, DestinationAddr: %s, DestinationPort: %d", convert.ActionToString(event.Action), bytes.Trim(event.Comm[:], "\x00"), convert.ProtoToString(event.Proto), net.IP(event.SAddr[:]), event.SPort, net.IP(event.DAddr[:]), event.DPort)
			case data := <-cA.icmpIngressChan:
				var event valueobject.ICMPEvent
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}

				log.Logger.Infof("a icmp ingress packet detected. action: %s, SourceAddr: %s, DestinationAddr: %s, Version: ICMPv%d, Type: %d, Code: %d", convert.ActionToString(event.Action), convert.Ntoa(event.SAddr), convert.Ntoa(event.DAddr), event.Version, event.Type, event.Code)

			case data := <-cA.icmpIngress6Chan:
				var event valueobject.ICMP6Event
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}
				if event.Type == constant.NeighborSolicitation || event.Type == constant.NeighborAdvertisement {
					log.Logger.Infof("This packet is used for mac address resolution, so let it pass by default.  action: %s, SourceAddr: %s, DestinationAddr: %s, Version: ICMPv%d, Type: %d, Code: %d", convert.ActionToString(event.Action), net.IP(event.SAddr[:]), net.IP(event.DAddr[:]), event.Version, event.Type, event.Code)
				} else {
					log.Logger.Infof("a icmp ingress packet detected. action: %s, SourceAddr: %s, DestinationAddr: %s, Version: ICMPv%d, Type: %d, Code: %d", convert.ActionToString(event.Action), net.IP(event.SAddr[:]), net.IP(event.DAddr[:]), event.Version, event.Type, event.Code)
				}

			case data := <-cA.icmpEgressChan:
				var event valueobject.ICMPEvent
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}

				log.Logger.Infof("a icmp egress packet detected. action: %s, SourceAddr: %s, DestinationAddr: %s, Version: ICMPv%d, Type: %d, Code: %d", convert.ActionToString(event.Action), convert.Ntoa(event.SAddr), convert.Ntoa(event.DAddr), event.Version, event.Type, event.Code)

			case data := <-cA.icmpEgress6Chan:
				var event valueobject.ICMP6Event
				err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
				if err != nil {
					log.Logger.Errorf("failed to decode received data: %+v\n", err)
					continue
				}
				if event.Type == constant.NeighborSolicitation || event.Type == constant.NeighborAdvertisement {
					log.Logger.Infof("This packet is used for mac address resolution, so let it pass by default. action: %s, SourceAddr: %s, DestinationAddr: %s, Version: ICMPv%d ,Type: %d, Code: %d", convert.ActionToString(event.Action), net.IP(event.SAddr[:]), net.IP(event.DAddr[:]), event.Version, event.Type, event.Code)
				} else {
					log.Logger.Infof("a icmp egress packet detected. action: %s, SourceAddr: %s, DestinationAddr: %s, Version: ICMPv%d, Type: %d, Code: %d", convert.ActionToString(event.Action), net.IP(event.SAddr[:]), net.IP(event.DAddr[:]), event.Version, event.Type, event.Code)
				}

			case event := <-channel2:
				log.Logger.Debugf("%+v\n", event)
			case err := <-errorChannel:
				log.Logger.Errorf("%+v\n", err)
			}
		}
	}()
	pA.connectPerfMap.Start()
	pA.connect6PerfMap.Start()
	pA.bindPerfMap.Start()
	pA.closePerfMap.Start()
	pA.ingressPerfMap.Start()
	pA.ingress6PerfMap.Start()
	pA.egressPerfMap.Start()
	pA.egress6PerfMap.Start()
	pA.icmpIngressPerfMap.Start()
	pA.icmpIngress6PerfMap.Start()
	pA.icmpEgressPerfMap.Start()
	pA.icmpEgress6PerfMap.Start()
	if start != nil {
		start <- "start"
	}

	return func() {
		pA.bindPerfMap.Stop()
		pA.connect6PerfMap.Stop()
		pA.connectPerfMap.Stop()
		pA.closePerfMap.Stop()
		pA.ingressPerfMap.Stop()
		pA.ingress6PerfMap.Stop()
		pA.egressPerfMap.Stop()
		pA.egress6PerfMap.Stop()
		pA.icmpIngressPerfMap.Stop()
		pA.icmpIngress6PerfMap.Stop()
		pA.icmpEgressPerfMap.Stop()
		pA.icmpEgress6PerfMap.Stop()
	}, nil
}
