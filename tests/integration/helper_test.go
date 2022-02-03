package integration

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"unsafe"

	"go.uber.org/zap"
	zapobserver "go.uber.org/zap/zaptest/observer"

	"furui/cmd"
	"furui/domain/entity"
	"furui/driver"
	"furui/infrastructure/docker"
	"furui/infrastructure/loader"
	"furui/infrastructure/log"
	containerRepo "furui/infrastructure/repository/impl/container"
	policyRepo "furui/infrastructure/repository/impl/policy"
	processRepo "furui/infrastructure/repository/impl/process"
	containerRepoIf "furui/infrastructure/repository/interface/container"
	policyRepoIf "furui/infrastructure/repository/interface/policy"
	processRepoIf "furui/infrastructure/repository/interface/process"
)

type Runnable interface {
	Run(sig chan os.Signal, start chan string)
}

type RouterRunner struct {
	loader              loader.Loader
	router              cmd.Router
	policyRepository    policyRepoIf.Repository
	containerRepository containerRepoIf.Repository
	processRepository   processRepoIf.Repository
	dockerInfra         docker.Docker
	containers          *entity.Containers
	policies            []*entity.Policy
}

func (r *RouterRunner) Run(sig chan os.Signal, start chan string) {
	cmd.Execute(r.loader, r.router, r.policyRepository, r.containerRepository, r.processRepository, r.dockerInfra, r.containers, r.policies, sig, start)
}

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

// extractLog returns the message as a string in the Log.
func extractLog(t *testing.T, runnable Runnable, sig chan os.Signal, start chan string) (string, error) {
	t.Helper()

	// Make it possible to retrieve and handle the logs spit out by zap
	core, obs := zapobserver.New(zap.InfoLevel)

	logger := zap.New(core)
	// Replace logger
	log.Logger = log.NewZapLogger(logger)

	// Execute the function under test.
	runnable.Run(sig, start)

	// Extracts only the message and concatenates it into a single string.
	all := obs.All()
	res := make([]byte, 0, len(all))
	for _, each := range all {
		res = append(res, each.Message...)
	}

	return *(*string)(unsafe.Pointer(&res)), nil
}

// runCmd will execute the command passed as argument in a different namespace
func runCmd(t *testing.T, doRunInContainer bool, args ...string) string {
	t.Helper()
	var cmd *exec.Cmd
	if doRunInContainer {
		args = append([]string{"--pid", "--fork"}, args...)
		// Run with the unshare command to isolate the namespace
		cmd = exec.Command("unshare", args...)
	} else {
		// Execute commands without isolating namespace
		cmd = exec.Command(args[0], args[1:]...) // #nosec // It's a test, so it's not a problem.
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("failed to run the cmd: %s err: %s\n", cmd, err)
		return *(*string)(unsafe.Pointer(&output))
	}

	return *(*string)(unsafe.Pointer(&output))
}

func Prepare(t *testing.T) (l loader.Loader, r cmd.Router, policyRepository policyRepoIf.Repository, containerRepository containerRepoIf.Repository, processRepository processRepoIf.Repository, dockerInfra docker.Docker, containers *entity.Containers, sig chan os.Signal, start chan string) {
	t.Helper()

	bindProg := readFile(t, "../../usecase/ebpf/bind.c")
	connectProg := readFile(t, "../../usecase/ebpf/connect.c")
	closeProg := readFile(t, "../../usecase/ebpf/close.c")
	ingressProg := readFile(t, "../../usecase/ebpf/ingress.c")
	egressProg := readFile(t, "../../usecase/ebpf/egress.c")
	icmpIngressProg := readFile(t, "../../usecase/ebpf/icmp_ingress.c")
	icmpEgressProg := readFile(t, "../../usecase/ebpf/icmp_egress.c")

	dockerInfra = docker.New(driver.DockerCLI())

	containers = entity.NewContainers(nil)

	err := dockerInfra.AddRunningContainersInspect(containers)
	if err != nil {
		t.Fatalf("failed to get containers information: %+v", err)
		return
	}

	l = loader.NewLoader(bindProg, connectProg, closeProg, ingressProg, egressProg, icmpIngressProg, icmpEgressProg)
	bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule, err := l.LoadModules()
	if err != nil {
		t.Fatalf("failed to load modules: %+v", err)
		return
	}
	policyRepository = policyRepo.NewPolicyRepository(ingressModule, icmpIngressModule)
	containerRepository = containerRepo.NewContainerRepository(ingressModule)
	processRepository = processRepo.NewProcessRepository(bindModule)
	r = cmd.NewRouter(bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule)

	sig = make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	start = make(chan string, 1)

	t.Cleanup(func() {
		err = l.UnLoadModules(bindModule, connectModule, closeModule, ingressModule, egressModule, icmpIngressModule, icmpEgressModule)
		if err != nil {
			t.Errorf("failed to unload modules: %+v", err)
			return
		}
	})

	return
}

func ClearPolicy(t *testing.T, r cmd.Router, policies []*entity.Policy) {
	t.Helper()
	policyRepository := policyRepo.NewPolicyRepository(r.GetIngressModule(), r.GetICMPIngressModule())
	t.Log(policies)
	if err := policyRepository.Delete(policies); err != nil {
		t.Fatalf("failed to delete policies : %+v", err)
		return
	}
}
