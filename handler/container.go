package handler

import (
	"furui/constant"
	"furui/domain/entity"
	"furui/infrastructure/docker"
	"furui/infrastructure/loader"
	"furui/infrastructure/log"
	policyInfra "furui/infrastructure/policy"
	containerRepo "furui/infrastructure/repository/interface/container"
	policyRepo "furui/infrastructure/repository/interface/policy"
	"furui/infrastructure/repository/interface/process"
	"furui/pkg/policy"
)

type container struct {
	docker      docker.Docker
	repo        containerRepo.Repository
	processRepo process.Repository
	policyRepo  policyRepo.Repository
}

func NewContainer(docker docker.Docker, repo containerRepo.Repository, processRepo process.Repository, policyRepo policyRepo.Repository) *container {
	return &container{docker: docker, repo: repo, processRepo: processRepo, policyRepo: policyRepo}
}

func (h container) AddDockerContainerInspection(cid string, containers *entity.Containers, loader loader.Loader, policyRepository policyRepo.Repository, policies []*entity.Policy, policiesChan chan []*entity.Policy) {
	container := entity.NewContainer()

	err := h.docker.SetContainerInspect(container, cid)
	if err != nil {
		log.Logger.Warnf("failed to add the container inspection: %s", err.Error())
	}

	containers.Add(container)
	log.Logger.Infof("the container inspection added: %s", container.ID)

	err = h.repo.SaveIDWithIPs(containers)
	if err != nil {
		log.Logger.Errorf("failed to save container to ebpf map: %s", err.Error())
		return
	}

	if err = policyRepository.Delete(policies); err != nil {
		log.Logger.Fatalf("failed to delete policies : %+v", err)
		return
	}

	// Load policies from policyPath
	policies, err = policyInfra.LoadPolicy(constant.PolicyPath, containers)
	if err != nil {
		log.Logger.Fatalf("failed to load policy path: %s , error: %+v", constant.PolicyPath, err)
		return
	}

	log.Logger.Infof("success to load policy: %+v", policies)

	policies, err = policy.ArrangePolicy(policies, containers)
	if err != nil {
		log.Logger.Errorf("failed to arrange policies: %s", err.Error())
	}

	if err = policyRepository.Save(policies); err != nil {
		log.Logger.Fatalf("failed to store policies : %+v", err)
		return
	}

	// TODO: It's not possible with the current functionality to check the veth of the container you started, so I'm reattaching it to everything https://github.com/moby/moby/issues/17064
	// Re-attach the program to all interfaces.
	_, _, _, _, err = loader.AttachProgsToQdisc()
	if err != nil {
		log.Logger.Errorf("failed to attach programs to qdisc: %s", err.Error())
		return
	}

	log.Logger.Infof("success to attach programs to qdisc")

	err = h.policyRepo.Save(policies)
	if err != nil {
		log.Logger.Errorf("failed to save policies to ebpf map: %s", err.Error())
		return
	}

	policiesChan <- policies
}

func (h container) RemoveDockerContainerInspection(cid string, containers *entity.Containers, policyRepository policyRepo.Repository, policies []*entity.Policy, policiesChan chan []*entity.Policy) {
	container := containers.Get(cid)

	err := h.repo.RemoveIDFromIPs(container)
	if err != nil {
		log.Logger.Warnf("failed to delete container from ebpf map: %s", err.Error())
	}

	if err = policyRepository.Delete(policies); err != nil {
		log.Logger.Fatalf("failed to delete policies : %+v", err)
		return
	}

	// Load policies from policyPath
	policies, err = policyInfra.LoadPolicy(constant.PolicyPath, containers)
	if err != nil {
		log.Logger.Fatalf("failed to load policy path: %s , error: %+v", constant.PolicyPath, err)
		return
	}

	log.Logger.Infof("success to load policy: %+v", policies)

	policies, err = policy.ArrangePolicy(policies, containers)
	if err != nil {
		log.Logger.Warnf("failed to arrange policies: %s", err.Error())
	}

	if err = policyRepository.Save(policies); err != nil {
		log.Logger.Fatalf("failed to store policies : %+v", err)
		return
	}

	// If the container disappears, veth also disappears, so don't detach the program explicitly.

	containers.Remove(cid)
	log.Logger.Infof("the container inspection removed: %s", cid)
	policiesChan <- policies
}
