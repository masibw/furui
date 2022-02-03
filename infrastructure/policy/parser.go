package policy

import (
	"io/ioutil"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"

	"furui/domain/entity"
	"furui/infrastructure/log"
	"furui/pkg/convert"
)

type Parser interface {
	Load(path string) ([]byte, error)
	Parse(rawPolicyData []byte, containers *entity.Containers) ([]*entity.Policy, error)
}

type YamlPolicies struct {
	Policies []struct {
		Container struct {
			Name string `yaml:"name"`
		}
		Communications []struct {
			Executable string `yaml:"executable"`
			Sockets    []struct {
				Protocol   string `yaml:"protocol"`
				LocalPort  uint16 `yaml:"local_port"`
				RemoteHost string `yaml:"remote_host"`
				RemotePort uint16 `yaml:"remote_port"`
			}

			ICMP []struct {
				Version    uint8  `yaml:"version"`
				Type       uint8  `yaml:"type"`
				Code       uint8  `yaml:"code"`
				RemoteHost string `yaml:"remote_host"`
			}
		}
	}
}

func (y *YamlPolicies) ToPolicies(containers *entity.Containers) (policies []*entity.Policy, err error) {
	policies = make([]*entity.Policy, len(y.Policies))
	for i, yamlPolicy := range y.Policies {
		parsedPolicy := &entity.Policy{
			Container: &entity.Container{
				Name: yamlPolicy.Container.Name,
			},
		}

		policies[i] = parsedPolicy
		parsedPolicy.Communications = make([]*entity.Communication, 0, len(yamlPolicy.Communications))
		for _, yamlCommunication := range yamlPolicy.Communications {
			parsedCommunication := &entity.Communication{}
			parsedCommunication.Process = yamlCommunication.Executable
			parsedCommunication.Sockets = make([]*entity.Socket, 0, len(yamlCommunication.Sockets))
			for _, yamlSocket := range yamlCommunication.Sockets {
				parsedSocket := &entity.Socket{
					LocalPort:  yamlSocket.LocalPort,
					RemotePort: yamlSocket.RemotePort,
				}
				protocol := strings.ToLower(yamlSocket.Protocol)

				switch protocol {
				case "tcp":
					parsedSocket.Protocol = "tcp"
				case "udp":
					parsedSocket.Protocol = "udp"
					// TODO: Error if unsupported protocol? -> There is a yaml validator, so you can use that too.
				}
				//	TODO: CIDR
				if yamlSocket.RemoteHost == "" {
					parsedCommunication.Sockets = append(parsedCommunication.Sockets, parsedSocket)
					continue
				}

				addrs := convert.RemoteHostToIPs(containers, yamlSocket.RemoteHost)
				for _, addr := range addrs {
					parsedCommunication.Sockets = append(parsedCommunication.Sockets, &entity.Socket{
						Protocol:   parsedSocket.Protocol,
						LocalPort:  parsedSocket.LocalPort,
						RemoteIP:   addr,
						RemotePort: parsedSocket.RemotePort,
					})
				}
			}
			parsedCommunication.ICMP = make([]*entity.ICMP, 0, len(yamlCommunication.ICMP))
			for _, yamlICMP := range yamlCommunication.ICMP {
				if yamlICMP.RemoteHost == "" {
					parsedCommunication.ICMP = append(parsedCommunication.ICMP, &entity.ICMP{
						Version: yamlICMP.Version,
						Type:    yamlICMP.Type,
						Code:    yamlICMP.Code,
					})
					continue
				}
				addrs := convert.RemoteHostToIPs(containers, yamlICMP.RemoteHost)
				for _, addr := range addrs {
					parsedICMP := &entity.ICMP{
						Version:  yamlICMP.Version,
						Type:     yamlICMP.Type,
						Code:     yamlICMP.Code,
						RemoteIP: addr,
					}
					parsedCommunication.ICMP = append(parsedCommunication.ICMP, parsedICMP)
				}
			}
			parsedPolicy.Communications = append(parsedPolicy.Communications, parsedCommunication)
		}
	}
	return
}

type YamlParser struct {
}

func NewYamlParser() (parser *YamlParser) {
	parser = &YamlParser{}
	return
}

func (p *YamlParser) Load(path string) (rawPolicyData []byte, err error) {
	log.Logger.Debugf("trying to load policy path: %s", path)
	rawPolicyData, err = ioutil.ReadFile(path)
	return
}

func (p *YamlParser) Parse(rawPolicyData []byte, containers *entity.Containers) (policies []*entity.Policy, err error) {
	var yamlData YamlPolicies
	err = yaml.Unmarshal(rawPolicyData, &yamlData)
	if err != nil {
		err = xerrors.Errorf("failed to unmarshal yaml policy: %w", err)
		return
	}
	policies, err = yamlData.ToPolicies(containers)
	if err != nil {
		err = xerrors.Errorf("failed to yaml data to policies: %w", err)
		return
	}
	return
}
