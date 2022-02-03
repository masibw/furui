package driver

import (
	"context"
	"path/filepath"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"

	"furui/infrastructure/log"
)

var (
	dockerCLI *client.Client
)

type DockerNotifier struct {
	Messages <-chan events.Message
	Err      <-chan error
	runCh    chan string
	killCh   chan string
	errCh    chan error
}

func init() {
	log.Logger.Debugf("trying to initialize docker engine api client")

	var err error
	dockerCLI, err = client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Logger.Fatalf("failed to initialize docker engine api client")
	}
}

func DockerCLI() *client.Client {
	return dockerCLI
}

func NewDockerNotifier(runCh chan string, killCh chan string, errCh chan error) *DockerNotifier {
	notifier := DockerNotifier{runCh: runCh, killCh: killCh, errCh: errCh}

	log.Logger.Debugf("trying to fetch docker container inspection")

	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("event", "start")
	filter.Add("event", "unpause")
	filter.Add("event", "pause")
	filter.Add("event", "die")

	notifier.Messages, notifier.Err = dockerCLI.Events(context.Background(), types.EventsOptions{Filters: filter})
	return &notifier
}

func (n *DockerNotifier) Start() {
	log.Logger.Debugf("trying to start docker event monitoring")

	defer close(n.runCh)
	defer close(n.killCh)
	defer close(n.errCh)

	lastRun := ""
	lastKill := ""
	for {
		select {
		case msg := <-n.Messages:
			log.Logger.Debugf("docker event received: %+v", msg)
			switch msg.Action {
			case "start", "unpause":
				cid := filepath.Base(msg.ID)
				if lastRun == cid {
					continue
				}
				n.runCh <- cid
				lastRun = cid
			case "pause", "die":
				cid := filepath.Base(msg.ID)
				if cid == lastKill {
					continue
				}
				n.killCh <- cid
				lastKill = cid
			}
		case err := <-n.Err:
			log.Logger.Debugf("docker error event received: %s", err.Error())
			n.errCh <- err
		}
	}
}
