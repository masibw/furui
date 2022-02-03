#include <bcc/proto.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pid_namespace.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <uapi/linux/bpf.h>

#define DROP 1
#define PASS 2
#define ETH_HLEN 14
#define IPV6_LEN 16

struct ingress_t {
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  u8 proto;
  u8 action;
  char comm[TASK_COMM_LEN];
};

struct ingress6_t {
  char saddr[IPV6_LEN];
  char daddr[IPV6_LEN];
  u16 sport;
  u16 dport;
  u8 proto;
  u8 action;
  char comm[TASK_COMM_LEN];
};

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

BPF_TABLE("extern", struct port_key, struct port_val, proc_ports, 20480);
BPF_PERF_OUTPUT(ingress_events);
BPF_PERF_OUTPUT(ingress6_events);

struct policy_key {
  char container_id[16];
  char comm[TASK_COMM_LEN];
  u32 remote_ip;
  char remote_ipv6[IPV6_LEN];
  u16 local_port;
  u16 remote_port;
  u8 protocol;
};

struct policy_val {
  char comm[TASK_COMM_LEN];
  u32 remote_ip;
  char remote_ipv6[IPV6_LEN];
  u16 local_port;
  u16 remote_port;
  u8 protocol;
};

// Structure that holds the policy
BPF_TABLE_PUBLIC("hash", struct policy_key, struct policy_val, policy_list,
                 256);

struct container_id_t {
  char container_id[16];
};

struct container_ip_t {
  u32 ip;
  char ipv6[IPV6_LEN];
};

// Save the container ID from the IP address so that it can be retrievedMap
BPF_TABLE_PUBLIC("hash", struct container_ip_t, struct container_id_t,
                 container_id_from_ips, 256);

int ingress(struct __sk_buff *skb) {
  u8 isSHOT = 0;
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;
  struct ingress_t event = {};
  struct ingress6_t event6 = {};
  u64 nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return TC_ACT_OK;

  u8 proto = 0;
  struct container_id_t *id_val;
  if (eth->h_proto == htons(ETH_P_IP)) {
    struct iphdr *iph = data + nh_off;
    if ((void *)&iph[1] > data_end)
      return TC_ACT_OK;

    event.saddr = iph->saddr;
    event.daddr = iph->daddr;
    // Determine what the next (L4)protocol is.
    event.proto = iph->protocol;
    proto = iph->protocol;
    nh_off += sizeof(struct iphdr);

    if (data + nh_off > data_end)
      return TC_ACT_OK;

    // Identify the container ID from the destination IP address.
    struct container_ip_t ip_key = {};
    // Since docker0 is located between the host and the container, it is in the
    // host byte order (little endian).
    ip_key.ip = iph->daddr;

    id_val = container_id_from_ips.lookup(&ip_key);
    // DROP later to output information such as ports even if the process could
    // not be identified.
    if (id_val == 0) {
      isSHOT = 1;
    }
  } else if (eth->h_proto == htons(ETH_P_IPV6)) {
    struct ipv6hdr *iph = data + nh_off;
    if ((void *)&iph[1] > data_end)
      return TC_ACT_OK;

    bpf_probe_read_kernel(&event6.saddr, sizeof(event6.saddr), &iph->saddr);
    bpf_probe_read_kernel(&event6.daddr, sizeof(event6.daddr), &iph->daddr);
    // Determine what the next (L4)protocol is.
    event6.proto = iph->nexthdr;
    proto = iph->nexthdr;
    nh_off += sizeof(struct ipv6hdr);

    if (data + nh_off > data_end)
      return TC_ACT_OK;

    // Identify the container ID from the destination IP address.
    struct container_ip_t ip_key = {};
    bpf_probe_read_kernel(&ip_key.ipv6, sizeof(ip_key.ipv6), &iph->daddr);

    id_val = container_id_from_ips.lookup(&ip_key);
    // DROP later to output information such as ports even if the process could
    // not be identified.
    if (id_val == 0) {
      isSHOT = 1;
    }
  }

  if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
    if (eth->h_proto == htons(ETH_P_IP)) {
      event.action = PASS;
      event.saddr = ntohl(event.saddr);
      event.daddr = ntohl(event.daddr);
      event.sport = ntohs(event.sport);
      event.dport = ntohs(event.dport);
      ingress_events.perf_submit_skb(skb, skb->len, &event, sizeof(event));
    } else if (eth->h_proto == htons(ETH_P_IPV6)) {
      event6.action = PASS;
      event6.sport = ntohs(event6.sport);
      event6.dport = ntohs(event6.dport);
      ingress6_events.perf_submit_skb(skb, skb->len, &event6, sizeof(event6));
    }
    return TC_ACT_OK;
  }

  u16 sport = 0;
  u16 dport = 0;
  if (proto == IPPROTO_TCP) {
    struct tcphdr *tcph = data + nh_off;
    if (data + nh_off + sizeof(struct tcphdr) > data_end)
      return TC_ACT_OK;
    sport = tcph->source;
    dport = tcph->dest;
  } else if (proto == IPPROTO_UDP) {
    struct udphdr *udph = data + nh_off;
    if (data + nh_off + sizeof(struct udphdr) > data_end)
      return TC_ACT_OK;
    sport = udph->source;
    dport = udph->dest;
  }

  if (isSHOT) {
    if (eth->h_proto == htons(ETH_P_IP)) {
      event.action = DROP;
      event.saddr = ntohl(event.saddr);
      event.daddr = ntohl(event.daddr);
      event.sport = ntohs(event.sport);
      event.dport = ntohs(event.dport);
      ingress_events.perf_submit_skb(skb, skb->len, &event, sizeof(event));
    } else if (eth->h_proto == htons(ETH_P_IPV6)) {
      event6.action = DROP;
      event6.sport = ntohs(event6.sport);
      event6.dport = ntohs(event6.dport);
      ingress6_events.perf_submit_skb(skb, skb->len, &event6, sizeof(event6));
    }
    return TC_ACT_SHOT;
  }

  // Get process names from proc_ports and policies from policy_list to make
  // decisions.
  struct port_key p_key = {};
  bpf_probe_read_kernel_str(&p_key.container_id, sizeof(p_key.container_id),
                            (void *)id_val->container_id);
  p_key.port = ntohs(dport);
  p_key.proto = proto;
  struct port_val *p_val;
  p_val = proc_ports.lookup(&p_key);
  if (!p_val) {
    if (eth->h_proto == htons(ETH_P_IP)) {
      event.action = DROP;
      event.saddr = ntohl(event.saddr);
      event.daddr = ntohl(event.daddr);
      event.sport = ntohs(sport);
      event.dport = ntohs(dport);
      ingress_events.perf_submit_skb(skb, skb->len, &event, sizeof(event));
    } else if (eth->h_proto == htons(ETH_P_IPV6)) {
      event6.action = DROP;
      event6.sport = ntohs(event6.sport);
      event6.dport = ntohs(event6.dport);
      ingress6_events.perf_submit_skb(skb, skb->len, &event6, sizeof(event6));
    }
    return TC_ACT_SHOT;
  }

  // Check against policy based on the information.
  struct policy_key policy_k = {};
  bpf_probe_read_kernel_str(&policy_k.container_id,
                            sizeof(policy_k.container_id),
                            (void *)id_val->container_id);
  bpf_probe_read_kernel_str(&policy_k.comm, sizeof(policy_k.comm),
                            (void *)p_val->comm);
  struct policy_val *policy_v;
  // If nothing is specified in the policy except the container name and
  // executable name, allow all communication to that process.
  policy_v = policy_list.lookup(&policy_k);
  if (policy_v) {
    goto pass;
  }

  if (eth->h_proto == htons(ETH_P_IP)) {
    bpf_probe_read_kernel(&event.comm, sizeof(event.comm), (void *)p_val->comm);
    event.sport = sport;
    event.dport = dport;
    //  Check in the order of protocol, local_port, remote_ip, remote_port
    policy_k.protocol = event.proto;
    policy_k.local_port = 0;
    policy_k.remote_ip = 0;
    policy_k.remote_port = 0;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }
    policy_k.local_port = ntohs(event.dport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }
    policy_k.remote_ip = event.saddr;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }
    policy_k.remote_port = ntohs(event.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }

    // Check in the order of local_port, remote_ip, remote_port
    // The default value for protocol is 255.
    policy_k.protocol = 255;
    policy_k.local_port = ntohs(event.dport);
    policy_k.remote_ip = 0;
    policy_k.remote_port = 0;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }
    policy_k.remote_ip = event.saddr;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }
    policy_k.remote_port = ntohs(event.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }

    // Check in the order of protocol, remote_ip, remote_port
    policy_k.protocol = event.proto;
    policy_k.local_port = 0;
    policy_k.remote_port = 0;
    policy_k.remote_ip = event.saddr;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }

    policy_k.remote_port = ntohs(event.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }

    // Check the combination of protocol and remote_port
    policy_k.local_port = 0;
    policy_k.remote_ip = 0;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }

    // Check in the order of local_port, remote_ip, remote_port
    // The default value for protocol is 255.
    policy_k.protocol = 255;
    policy_k.local_port = ntohs(event.dport);
    policy_k.remote_ip = 0;
    policy_k.remote_port = 0;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }
    policy_k.remote_ip = event.saddr;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }
    policy_k.remote_port = ntohs(event.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }

    // Check the combination of local_port and remote_port
    policy_k.protocol = 255;
    policy_k.local_port = ntohs(event.dport);
    policy_k.remote_ip = 0;
    policy_k.remote_port = ntohs(event.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }

    // Check in the order of remote_ip, remote_port
    policy_k.protocol = 255;
    policy_k.local_port = 0;
    policy_k.remote_ip = event.saddr;
    policy_k.remote_port = 0;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }
    policy_k.remote_port = ntohs(event.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }

    // Check in the order of remote_port
    policy_k.protocol = 255;
    policy_k.local_port = 0;
    policy_k.remote_ip = 0;
    policy_k.remote_port = ntohs(event.dport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass;
    }

    event.action = DROP;
    event.saddr = ntohl(event.saddr);
    event.daddr = ntohl(event.daddr);
    event.sport = ntohs(event.sport);
    event.dport = ntohs(event.dport);
    ingress_events.perf_submit_skb(skb, skb->len, &event, sizeof(event));
    return TC_ACT_SHOT;
  } else if (eth->h_proto == htons(ETH_P_IPV6)) {
    bpf_probe_read_kernel(&event6.comm, sizeof(event6.comm),
                          (void *)p_val->comm);
    event6.sport = sport;
    event6.dport = dport;

    // Check in the order of protocol, local_port, remote_ip, remote_port
    policy_k.protocol = event6.proto;
    policy_k.local_port = 0;
    policy_k.remote_port = 0;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }
    policy_k.local_port = ntohs(event6.dport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }
    bpf_probe_read_kernel(&policy_k.remote_ipv6, sizeof(policy_k.remote_ipv6),
                          &event6.saddr);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }
    policy_k.remote_port = ntohs(event6.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }

    //  Check the combination of protocol and remote_ip
    policy_k.local_port = 0;
    policy_k.remote_port = 0;
    bpf_probe_read_kernel(&policy_k.remote_ipv6, sizeof(policy_k.remote_ipv6),
                          &event6.saddr);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }

    // Check the combination of protocol, remote_ip, and remote_port
    policy_k.remote_port = ntohs(event6.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }

    // Check the combination of protocol and remote_port
    policy_k.local_port = 0;
    for (int i = 0; i < IPV6_LEN; i++) {
      policy_k.remote_ipv6[i] = 0;
    }
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }

    // Check in the order of local_port, remote_ip, remote_port
    // The default value for protocol is 255.．
    policy_k.protocol = 255;
    policy_k.local_port = ntohs(event6.dport);
    for (int i = 0; i < IPV6_LEN; i++) {
      policy_k.remote_ipv6[i] = 0;
    }
    policy_k.remote_port = 0;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }
    bpf_probe_read_kernel(&policy_k.remote_ipv6, sizeof(policy_k.remote_ipv6),
                          &event6.saddr);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }
    policy_k.remote_port = ntohs(event6.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }

    // Check the combination of local_port and remote_port
    policy_k.protocol = 255;
    policy_k.local_port = ntohs(event6.dport);
    for (int i = 0; i < IPV6_LEN; i++) {
      policy_k.remote_ipv6[i] = 0;
    }
    policy_k.remote_port = ntohs(event6.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }

    // Check in the order of remote_ip, remote_port
    policy_k.protocol = 255;
    policy_k.local_port = 0;
    bpf_probe_read_kernel(&policy_k.remote_ipv6, sizeof(policy_k.remote_ipv6),
                          &event6.saddr);
    policy_k.remote_port = 0;
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }
    policy_k.remote_port = ntohs(event6.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }

    // Check in the order of remote_port
    policy_k.protocol = 255;
    policy_k.local_port = 0;
    for (int i = 0; i < IPV6_LEN; i++) {
      policy_k.remote_ipv6[i] = 0;
    }
    policy_k.remote_port = ntohs(event6.sport);
    policy_v = policy_list.lookup(&policy_k);
    if (policy_v) {
      goto pass6;
    }

    event6.action = DROP;
    event6.sport = ntohs(event6.sport);
    event6.dport = ntohs(event6.dport);
    ingress6_events.perf_submit_skb(skb, skb->len, &event6, sizeof(event6));
    return TC_ACT_SHOT;
  }
pass:
  event.action = PASS;
  event.saddr = ntohl(event.saddr);
  event.daddr = ntohl(event.daddr);
  event.sport = ntohs(event.sport);
  event.dport = ntohs(event.dport);
  ingress_events.perf_submit_skb(skb, skb->len, &event, sizeof(event));
  return TC_ACT_OK;

pass6:
  event6.action = PASS;
  event6.sport = ntohs(event6.sport);
  event6.dport = ntohs(event6.dport);
  ingress6_events.perf_submit_skb(skb, skb->len, &event6, sizeof(event6));
  return TC_ACT_OK;
}