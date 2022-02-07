# furui

Communication control of the container runtime environment(now only docker) is performed using eBPF.

# Caution

This system has several problems and is not recommended for use in a production environment.

- Since this system uses Kprobe, even a small difference in kernel may cause it to not work.
- We are attaching the BPF program to an interface that starts with the name veth, which may control communication with non-docker containers.
- The tc command is invoked with exec.Command, which takes veth name as an argument. I'm assuming it's not a problem since can't use shell pipes in exec.Command, but I'm not sure.
- Since map is used to store process information, there is a possibility that if the capacity of map is exceeded, control will not be possible.

# Operation check environment

- OS: Ubuntu 20.04.3 LTS (Focal Fossa)
- kernel version: 5.10.0-051000-generic
- [bcc](https://github.com/iovisor/bcc)(commit hash: 220c6dc6bb62c79d5eff49efa5c98e786bf62d4a)
- Docker: Docker version 20.10.9, build c2ea9bc

# How to use

To start it, you need to put `policy.yml`, which describes the availability of communication, in the directory where the command is executed.
For `policy.yml`, please refer to [examples](./examples).

## How to run

You can get binary from Releases or compile from source code.
Then, run below command.

```bash
sudo -E ./furui
```

If you want to display the debug information as well

```bash
sudo -E ENV=debug ./furui
```


## Performance

See [./docs/performance.md](./docs/performance.md)

## How to contribute

See [./docs/development.md](./docs/development.md)

# Special Thanks

[@ken109](https://github.com/ken109) , [@ishii211](https://github.com/ishii211), [@mitchy54](https://github.com/mitchy54), [@tatsuniii666](https://github.com/tatsuniii666)
