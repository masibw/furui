package entity

import (
	"fmt"
	"net"
	"sync"

	"github.com/thoas/go-funk"

	"furui/constant"
)

type Container struct {
	ID          string
	IPAddresses []net.IP
	Name        string
	Pid         int
}

func NewContainer() *Container {
	return &Container{}
}

func (c *Container) String() string {
	return fmt.Sprintf("{ID: %s IPAddresses %v Name: %s Pid: %d", c.ID, c.IPAddresses, c.Name, c.Pid)
}

type Containers struct {
	mutex sync.RWMutex
	list  []*Container
}

func NewContainers(containers []*Container) *Containers {
	return &Containers{
		mutex: sync.RWMutex{},
		list:  containers,
	}
}

func (c *Containers) List() []*Container {
	return c.list
}

func (c *Containers) Add(container *Container) {
	c.mutex.Lock()
	c.list = append(c.list, container)
	c.mutex.Unlock()
}

func (c *Containers) Remove(cid string) {
	newList := funk.Filter(c.list, func(container *Container) bool {
		return container.ID != cid
	}).([]*Container)

	c.mutex.Lock()
	c.list = newList
	c.mutex.Unlock()
}

func (c *Containers) Get(cid string) *Container {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for _, container := range c.list {
		if container.ID == cid[:constant.ContainerIDLen] {
			return container
		}
	}

	return nil
}

func (c *Containers) GetFromName(cName string) *Container {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for _, container := range c.list {
		// Skip the / in the container name because it is prefixed with /, like /nginx
		if container.Name[1:] == cName {
			return container
		}
	}

	return nil
}
