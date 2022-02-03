#include <bcc/proto.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <net/inet_sock.h>

// A structure to identify the process using the port
struct port_key {
  char container_id[16];
  u16 port;
  u8 proto;
};

// A structure that stores information about the process using the port
struct port_val {
  char comm[TASK_COMM_LEN];
};

struct bind_t {
  // Only 12 characters are in the nodename, so it's 12+termination characters,
  // but I've set it to 16 for memory alignment reasons.
  char container_id[16];
  u32 pid;
  char comm[TASK_COMM_LEN];
  u16 family;
  u16 lport;
  // Defined at the very end for memory alignment.
  u8 proto;
};

// Make it PUBLIC to call from other BPF programs.
BPF_TABLE_PUBLIC("hash", struct port_key, struct port_val, proc_ports, 20480);
BPF_PERF_OUTPUT(bind_events);

// Monitor inet_bind to get information about the (server-side) process that
// started waiting in the container. Get the Pid, container ID, executable file
// name, port used, and protocol.

// TRACEPOINT(syscalls, sys_enter_bind) could not determine the protocol, so
// kprobe is used.
int trace_inet_bind(struct pt_regs *ctx, struct socket *sock,
                    const struct sockaddr *addr) {
  struct sock *sk = sock->sk;
  struct bind_t proc = {};

  // get pid
  proc.pid = bpf_get_current_pid_tgid();
  // get comm
  bpf_get_current_comm(proc.comm, TASK_COMM_LEN);

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  struct pid_namespace *pidns =
      (struct pid_namespace *)task->nsproxy->pid_ns_for_children;

  // check whether this process running in container(another namespace). 0=host
  if (pidns->level == 0) {
    return 0;
  }

  // get container_id
  struct uts_namespace *uts = (struct uts_namespace *)task->nsproxy->uts_ns;
  bpf_probe_read(&proc.container_id, sizeof(proc.container_id),
                 (void *)uts->name.nodename);

  // check IPv4/IPv6
  proc.family = sk->__sk_common.skc_family;
  if (proc.family == AF_INET) {

    struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
    proc.lport = in_addr->sin_port;
    // check TCP/UDP
    if (sk->sk_protocol == IPPROTO_TCP) {
      proc.proto = sk->sk_protocol;
      struct port_key key = {};
      key.port = ntohs(proc.lport);
      key.proto = sk->sk_protocol;
      bpf_probe_read(&key.container_id, sizeof(key.container_id),
                     (void *)uts->name.nodename);
      struct port_val val = {};
      bpf_get_current_comm(val.comm, TASK_COMM_LEN);
      proc_ports.update(&key, &val);
    } else if (sk->sk_protocol == IPPROTO_UDP) {
      proc.proto = sk->sk_protocol;
      struct port_key key = {};
      key.port = ntohs(proc.lport);
      key.proto = sk->sk_protocol;
      bpf_probe_read(&key.container_id, sizeof(key.container_id),
                     (void *)uts->name.nodename);
      struct port_val val = {};
      bpf_get_current_comm(val.comm, TASK_COMM_LEN);
      proc_ports.update(&key, &val);
    } else {
      // unsupported protocol
      return 0;
    }
    proc.lport = ntohs(proc.lport);
    bind_events.perf_submit(ctx, &proc, sizeof(proc));
  }
  return 0;
};

// For IPv6
int trace_inet6_bind(struct pt_regs *ctx, struct socket *sock,
                     const struct sockaddr *addr) {
  struct sock *sk = sock->sk;
  struct bind_t proc = {};

  // get pid
  proc.pid = bpf_get_current_pid_tgid();
  // get comm
  bpf_get_current_comm(proc.comm, TASK_COMM_LEN);

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  struct pid_namespace *pidns =
      (struct pid_namespace *)task->nsproxy->pid_ns_for_children;

  // check whether this process running in container(another namespace). 0=host
  if (pidns->level == 0) {
    return 0;
  }

  // get container_id
  struct uts_namespace *uts = (struct uts_namespace *)task->nsproxy->uts_ns;
  bpf_probe_read(&proc.container_id, sizeof(proc.container_id),
                 (void *)uts->name.nodename);

  // check IPv4/IPv6
  proc.family = sk->__sk_common.skc_family;
  if (proc.family == AF_INET6) {
    struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *)addr;
    proc.lport = in6_addr->sin6_port;
    proc.proto = sk->sk_protocol;
    struct port_key key = {};
    key.port = ntohs(proc.lport);
    key.proto = sk->sk_protocol;
    bpf_probe_read(&key.container_id, sizeof(key.container_id),
                   (void *)uts->name.nodename);
    struct port_val val = {};
    bpf_get_current_comm(val.comm, TASK_COMM_LEN);
    proc_ports.update(&key, &val);
    proc.lport = ntohs(proc.lport);
    bind_events.perf_submit(ctx, &proc, sizeof(proc));
  }
  return 0;
};