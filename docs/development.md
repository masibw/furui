
# Environment
Go 1.16+

## What you need for development
- clang-format
- golangci-lint

# Before (Create/Push) PR
to fix the appearance of the code
```
make format
```

Make sure that it passes the static analysis. However, if you are using a mac or windows, you may get an error because bcc.c is not available. This should be done on server (linux).
```
make lint
```

# Tests
Before running the test, you need to assign an IPv6 address to the container by writing the following in `/etc/docker/daemon.json` and restart docker daemon.
```
{
  "ipv6": true,
  "fixed-cidr-v6": "fe80::1:0/112"
}
```


```bash
make test-up
```

Automated tests can be run with the following commands.
```bash
sudo -E make test
```

However, as of 2021/12/31, it seems to fail if you run all tests at once, so it is better to run only the ones you want to test with `-run {test name}` as in the following command

```bash
sudo -E go test ./... -count=1 -cover -run TestIngress
```

It seems that this is caused by not being able to reset the BPF program environment for each test, but we don't know how to solve it.