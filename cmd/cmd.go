package cmd

import (
	"os"

	"furui/domain/entity"
	"furui/driver"
	"furui/handler"
	"furui/infrastructure/docker"
	"furui/infrastructure/loader"
	"furui/infrastructure/log"
	containerRepo "furui/infrastructure/repository/interface/container"
	policyRepo "furui/infrastructure/repository/interface/policy"
	processRepo "furui/infrastructure/repository/interface/process"
	pkgPolicy "furui/pkg/policy"
	"furui/usecase/go/proc"
)

//nolint:gocognit
// Execute initializes furui. (Load policy, DI, etc...)
func Execute(l loader.Loader, r Router, policyRepository policyRepo.Repository, containerRepository containerRepo.Repository, processRepository processRepo.Repository, dockerInfra docker.Docker, containers *entity.Containers, policies []*entity.Policy, sig chan os.Signal, start chan string) {
	var err error

	processes := proc.GetProcesses(containers)
	log.Logger.Debugf("processes: %+v", processes)

	policies, err = pkgPolicy.ArrangePolicy(policies, containers)
	if err != nil {
		log.Logger.Errorf("failed to arrange policies: %+v", err)
	}

	log.Logger.Infof("success to load policy: %+v", policies)

	if err = policyRepository.Save(policies); err != nil {
		log.Logger.Fatalf("failed to store policies : %+v", err)
		return
	}

	// Store the container ID in Map so that it can be retrieved from the IP address.
	if err = containerRepository.SaveIDWithIPs(containers); err != nil {
		log.Logger.Fatalf("failed to container's ip with id: %+v", err)
		return
	}

	if err = processRepository.SaveProcesses(processes); err != nil {
		log.Logger.Fatalf("failed to store processes: %+v", err)
		return
	}

	containerHandler := handler.NewContainer(dockerInfra, containerRepository, processRepository, policyRepository)

	runCh := make(chan string)
	killCh := make(chan string)
	runErrCh := make(chan error)

	notifier := driver.NewDockerNotifier(runCh, killCh, runErrCh)
	go notifier.Start()

	if clean, err := r.HandleEvents(start, processRepository, processes); err != nil {
		log.Logger.Fatalf("failed to handle events: %+v", err)
		return
	} else {
		defer clean()
	}

loop:
	for {
		select {
		case <-sig:
			log.Logger.Infof("the signal received")
			break loop
		case cid := <-runCh:
			policiesChan := make(chan []*entity.Policy)
			go containerHandler.AddDockerContainerInspection(cid, containers, l, policyRepository, policies, policiesChan)
			policies = <-policiesChan
		case cid := <-killCh:
			policiesChan := make(chan []*entity.Policy)
			go containerHandler.RemoveDockerContainerInspection(cid, containers, policyRepository, policies, policiesChan)
			policies = <-policiesChan
		case cid := <-runErrCh:
			log.Logger.Infof("an error occurred when starting the container: %s", cid)
		}
	}
}
