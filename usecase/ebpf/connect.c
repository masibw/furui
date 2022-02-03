#include <bcc/proto.h>
#include <linux/fs.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <net/inet_sock.h>
#include <net/ipv6.h>
#include <net/sock.h>
struct connect_t {
  // Only 12 characters are in the nodename, so it's 12+termination characters,
  // but I've set it to 16 for memory alignment reasons.
  char container_id[16];
  u32 pid;
  char comm[TASK_COMM_LEN];
  u32 src_addr;
  u32 dst_addr;
  u16 src_port;
  u16 dst_port;
  u16 family;
  u8 protocol;
};

struct connect6_t {
  // Only 12 characters are in the nodename, so it's 12+termination characters,
  // but I've set it to 16 for memory alignment reasons.
  char container_id[16];
  u32 pid;
  char comm[TASK_COMM_LEN];
  char src_addr[16];
  char dst_addr[16];
  u16 src_port;
  u16 dst_port;
  u16 family;
  u8 protocol;
};

BPF_PERF_OUTPUT(connect_events);
BPF_PERF_OUTPUT(connect6_events);

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

// Map for storing information about processes waiting on a port
BPF_TABLE("extern", struct port_key, struct port_val, proc_ports, 20480);

// Monitor to get information about the (client-side) process that started
// communication in the container. Obtain the Pid, Container ID, executable file
// name, source IP address, source port number, destination IP address and port
// number.
int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk) {
  // Only IPv4 & IPv6 is supported.
  if (sk->__sk_common.skc_family != AF_INET &&
      sk->__sk_common.skc_family != AF_INET6) {
    return 0;
  }

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct pid_namespace *pidns =
      (struct pid_namespace *)task->nsproxy->pid_ns_for_children;
  // check whether this process running in container(another namespace). 0=host
  if (pidns->level == 0) {
    return 0;
  }
  struct inet_sock *isk = inet_sk(sk);

  if (sk->__sk_common.skc_family == AF_INET) {
    struct connect_t connect = {};
    connect.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(connect.comm, TASK_COMM_LEN);

    // get container_id
    struct uts_namespace *uts = (struct uts_namespace *)task->nsproxy->uts_ns;
    bpf_probe_read(&connect.container_id, sizeof(connect.container_id),
                   (void *)uts->name.nodename);

    connect.src_addr = sk->__sk_common.skc_rcv_saddr;
    connect.dst_addr = sk->__sk_common.skc_daddr;
    connect.src_port = isk->inet_sport;
    connect.dst_port = sk->__sk_common.skc_dport;
    connect.protocol = IPPROTO_TCP;
    connect.family = AF_INET;
    struct port_key pkey = {};
    u16 sport = isk->inet_sport;
    pkey.port = ntohs(sport);
    pkey.proto = IPPROTO_TCP;
    bpf_probe_read(&pkey.container_id, sizeof(pkey.container_id),
                   (void *)uts->name.nodename);
    struct port_val val = {};
    bpf_get_current_comm(val.comm, TASK_COMM_LEN);
    proc_ports.update(&pkey, &val);

    connect.src_addr = ntohl(connect.src_addr);
    connect.dst_addr = ntohl(connect.dst_addr);
    connect.src_port = ntohs(connect.src_port);
    connect.dst_port = ntohs(connect.dst_port);
    connect_events.perf_submit(ctx, &connect, sizeof(connect));
  } else if (sk->__sk_common.skc_family == AF_INET6) {
    struct ipv6_pinfo *np = isk->pinet6;
    struct connect6_t connect = {};
    connect.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(connect.comm, TASK_COMM_LEN);

    // get container_id
    struct uts_namespace *uts = (struct uts_namespace *)task->nsproxy->uts_ns;
    bpf_probe_read(&connect.container_id, sizeof(connect.container_id),
                   (void *)uts->name.nodename);

    bpf_probe_read_kernel(&connect.src_addr, sizeof(connect.src_addr),
                          &np->saddr);
    bpf_probe_read_kernel(&connect.dst_addr, sizeof(connect.dst_addr),
                          &isk->sk.__sk_common.skc_v6_daddr);

    connect.src_port = isk->inet_sport;
    connect.dst_port = sk->__sk_common.skc_dport;
    connect.protocol = IPPROTO_TCP;
    connect.family = AF_INET6;
    struct port_key pkey = {};
    u16 sport = isk->inet_sport;
    pkey.port = ntohs(sport);
    pkey.proto = IPPROTO_TCP;
    bpf_probe_read(&pkey.container_id, sizeof(pkey.container_id),
                   (void *)uts->name.nodename);
    struct port_val val = {};
    bpf_get_current_comm(val.comm, TASK_COMM_LEN);
    proc_ports.update(&pkey, &val);

    connect.src_port = ntohs(connect.src_port);
    connect.dst_port = ntohs(connect.dst_port);
    connect6_events.perf_submit(ctx, &connect, sizeof(connect));
  }
  return 0;
}

int trace_udp_connect(struct pt_regs *ctx, struct sock *sk,
                      struct flowi4 *flow4) {
  // You don't need to check it, because only IPv4 is supposed to come in.
  // IPv6 is named udp_v6_send_skb
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct pid_namespace *pidns =
      (struct pid_namespace *)task->nsproxy->pid_ns_for_children;
  // check whether this process running in container(another namespace). 0=host
  if (pidns->level == 0) {
    return 0;
  }

  struct connect_t connect = {};
  connect.pid = bpf_get_current_pid_tgid();
  bpf_get_current_comm(connect.comm, TASK_COMM_LEN);

  // get container_id
  struct uts_namespace *uts = (struct uts_namespace *)task->nsproxy->uts_ns;
  bpf_probe_read(&connect.container_id, sizeof(connect.container_id),
                 (void *)uts->name.nodename);

  struct inet_sock *isk = inet_sk(sk);
  connect.src_addr = flow4->saddr;
  connect.dst_addr = flow4->daddr;
  connect.src_port = flow4->uli.ports.sport;
  connect.dst_port = flow4->uli.ports.dport;
  connect.protocol = IPPROTO_UDP;
  connect.family = AF_INET;
  struct port_key pkey = {};
  u16 sport = flow4->uli.ports.sport;
  pkey.port = ntohs(sport);
  pkey.proto = IPPROTO_UDP;
  bpf_probe_read(&pkey.container_id, sizeof(pkey.container_id),
                 (void *)uts->name.nodename);
  struct port_val val = {};
  bpf_get_current_comm(val.comm, TASK_COMM_LEN);
  proc_ports.update(&pkey, &val);

  connect.src_addr = ntohl(connect.src_addr);
  connect.dst_addr = ntohl(connect.dst_addr);
  connect.src_port = ntohs(connect.src_port);
  connect.dst_port = ntohs(connect.dst_port);
  connect_events.perf_submit(ctx, &connect, sizeof(connect));
  return 0;
}

int trace_udp6_connect(struct pt_regs *ctx, struct sk_buff *skb,
                       struct flowi6 *fl6, struct inet_cork *cork) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct pid_namespace *pidns =
      (struct pid_namespace *)task->nsproxy->pid_ns_for_children;
  // check whether this process running in container(another namespace). 0=host
  if (pidns->level == 0) {
    return 0;
  }

  struct connect6_t connect = {};
  connect.pid = bpf_get_current_pid_tgid();
  bpf_get_current_comm(connect.comm, TASK_COMM_LEN);

  // get container_id
  struct uts_namespace *uts = (struct uts_namespace *)task->nsproxy->uts_ns;
  bpf_probe_read(&connect.container_id, sizeof(connect.container_id),
                 (void *)uts->name.nodename);
  bpf_probe_read_kernel(&connect.src_addr, sizeof(connect.src_addr),
                        &fl6->saddr.in6_u);
  bpf_probe_read_kernel(&connect.dst_addr, sizeof(connect.dst_addr),
                        &fl6->daddr.in6_u);
  connect.src_port = fl6->uli.ports.sport;
  connect.dst_port = fl6->uli.ports.dport;
  connect.protocol = IPPROTO_UDP;
  connect.family = AF_INET6;
  struct port_key pkey = {};
  u16 sport = fl6->uli.ports.sport;
  pkey.port = ntohs(sport);
  pkey.proto = IPPROTO_UDP;
  bpf_probe_read(&pkey.container_id, sizeof(pkey.container_id),
                 (void *)uts->name.nodename);
  struct port_val val = {};
  bpf_get_current_comm(val.comm, TASK_COMM_LEN);
  proc_ports.update(&pkey, &val);

  connect.src_port = ntohs(connect.src_port);
  connect.dst_port = ntohs(connect.dst_port);
  connect6_events.perf_submit(ctx, &connect, sizeof(connect));
  return 0;
}