package main

import (
	_ "embed"
	"os"
	"os/signal"
	"syscall"

	"furui/cmd"
	"furui/constant"
	"furui/domain/entity"
	"furui/driver"
	"furui/infrastructure/docker"
	"furui/infrastructure/loader"
	"furui/infrastructure/log"
	"furui/infrastructure/policy"
	containerRepo "furui/infrastructure/repository/impl/container"
	policyRepo "furui/infrastructure/repository/impl/policy"
	processRepo "furui/infrastructure/repository/impl/process"
)

var (
	//go:embed usecase/ebpf/bind.c
	bindProg []byte

	//go:embed usecase/ebpf/connect.c
	connectProg []byte

	//go:embed usecase/ebpf/close.c
	closeProg []byte

	//go:embed usecase/ebpf/ingress.c
	ingressProg []byte

	//go:embed usecase/ebpf/egress.c
	egressProg []byte

	//go:embed usecase/ebpf/icmp_ingress.c
	icmpIngressProg []byte

	//go:embed usecase/ebpf/icmp_egress.c
	icmpEgressProg []byte
)

func main() {
	dockerInfra := docker.New(driver.DockerCLI())

	containers := entity.NewContainers(nil)

	err := dockerInfra.AddRunningContainersInspect(containers)
	if err != nil {
		log.Logger.Fatalf("failed to get containers information: %+v", err)
		return
	}
	log.Logger.Infof("success to get containers information: %+v", containers)

	// Load policies from policyPath
	policies, err := policy.LoadPolicy(constant.PolicyPath, containers)
	if err != nil {
		log.Logger.Fatalf("failed to load policy path: %s , error: %+v", constant.PolicyPath, err)
		return
	}

	l := loader.NewLoader(bindProg, connectProg, closeProg, ingressProg, egressProg, icmpIngressProg, icmpEgressProg)
	bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule, err := l.LoadModules()
	if err != nil {
		log.Logger.Fatalf("failed to load modules: %+v", err)
		return
	}
	policyRepository := policyRepo.NewPolicyRepository(ingressModule, icmpIngressModule)
	containerRepository := containerRepo.NewContainerRepository(ingressModule)
	processRepository := processRepo.NewProcessRepository(bindModule)
	r := cmd.NewRouter(bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	cmd.Execute(l, r, policyRepository, containerRepository, processRepository, dockerInfra, containers, policies, sig, nil)

	defer func() {
		err = policyRepository.Delete(policies)
		if err != nil {
			log.Logger.Errorf("failed to delete policies: %+v", err)
			return
		}

		err = l.UnLoadModules(bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule)
		if err != nil {
			log.Logger.Errorf("failed to unload modules: %+v", err)
			return
		}
	}()
}
