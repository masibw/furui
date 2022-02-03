#include <bcc/proto.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
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
#define NEIGHBOR_SOLICITAION 135
#define NEIGHBOR_ADVERTISEMENT 136
#define ICMPv4 4
#define ICMPv6 6

struct ingress_icmp {
  u32 saddr;
  u32 daddr;
  u8 version;
  u8 type;
  u8 code;
  u8 action;
};

struct ingress6_icmp {
  char saddr[IPV6_LEN];
  char daddr[IPV6_LEN];
  u8 version;
  u8 type;
  u8 code;
  u8 action;
};

BPF_PERF_OUTPUT(icmp_ingress);
BPF_PERF_OUTPUT(icmp_ingress6);

struct icmp_policy_key {
  char container_id[16];
  u8 version;
  u8 type;
  u8 code;
  u32 remote_ip;
  char remote_ipv6[IPV6_LEN];
};

struct icmp_policy_val {
  u8 version;
  u8 type;
  u8 code;
  u32 remote_ip;
  char remote_ipv6[IPV6_LEN];
};

// Structure that holds the policy
BPF_TABLE_PUBLIC("hash", struct icmp_policy_key, struct icmp_policy_val,
                 icmp_policy_list, 256);

struct container_id_t {
  char container_id[16];
};

struct container_ip_t {
  u32 ip;
  char ipv6[IPV6_LEN];
};

// Save the container ID from the IP address so that it can be retrievedMap
BPF_TABLE("extern", struct container_ip_t, struct container_id_t,
          container_id_from_ips, 256);

int ingress(struct __sk_buff *skb) {
  u8 isSHOT = 0;
  u8 proto = 0;
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;
  struct ingress_icmp icmp_event = {};
  struct ingress6_icmp icmp_event6 = {};
  u64 nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return TC_ACT_OK;

  struct container_id_t *id_val;
  if (eth->h_proto == htons(ETH_P_IP)) {
    struct iphdr *iph = data + nh_off;
    if ((void *)&iph[1] > data_end)
      return TC_ACT_OK;

    // Determine what the next (L4)protocol is.
    proto = iph->protocol;
    icmp_event.saddr = iph->saddr;
    icmp_event.daddr = iph->daddr;
    nh_off += sizeof(struct iphdr);

    if (data + nh_off > data_end)
      return TC_ACT_OK;

    // Identify the container ID from the destination IP address.
    struct container_ip_t ip_key = {};
    // Since docker0 is located between the host and the container, it is in the
    // host byte order (little endian).
    ip_key.ip = iph->daddr;

    id_val = container_id_from_ips.lookup(&ip_key);
    // DROP when the container with the retrieved IP address does not exist.
    if (id_val == 0) {
      isSHOT = 1;
    }
  } else if (eth->h_proto == htons(ETH_P_IPV6)) {
    struct ipv6hdr *iph = data + nh_off;
    if ((void *)&iph[1] > data_end)
      return TC_ACT_OK;

    bpf_probe_read_kernel(&icmp_event6.saddr, sizeof(icmp_event6.saddr),
                          &iph->saddr);
    bpf_probe_read_kernel(&icmp_event6.daddr, sizeof(icmp_event6.daddr),
                          &iph->daddr);
    // Determine what the next (L4)protocol is.
    proto = iph->nexthdr;
    nh_off += sizeof(struct ipv6hdr);

    if (data + nh_off > data_end)
      return TC_ACT_OK;

    // Identify the container ID from the destination IP address.
    struct container_ip_t ip_key = {};
    bpf_probe_read_kernel(&ip_key.ipv6, sizeof(ip_key.ipv6), &iph->daddr);
    id_val = container_id_from_ips.lookup(&ip_key);
    //  DROP when the container with the retrieved IP address does not exist.
    if (id_val == 0) {
      isSHOT = 1;
    }
  }

  if (proto != IPPROTO_ICMP && proto != IPPROTO_ICMPV6) {
    return TC_ACT_PIPE;
  }
  if (eth->h_proto == htons(ETH_P_IP)) {
    struct icmphdr *ich = data + nh_off;
    if (data + nh_off + sizeof(struct icmphdr) > data_end)
      return TC_ACT_OK;
    icmp_event.version = ICMPv4;
    icmp_event.type = ich->type;
    icmp_event.code = ich->code;
  } else if (eth->h_proto == htons(ETH_P_IPV6)) {
    struct icmp6hdr *ich6 = data + nh_off;
    if (data + nh_off + sizeof(struct icmp6hdr) > data_end)
      return TC_ACT_OK;
    icmp_event6.version = ICMPv6;
    icmp_event6.type = ich6->icmp6_type;
    icmp_event6.code = ich6->icmp6_code;
    if (icmp_event6.type == NEIGHBOR_SOLICITAION ||
        icmp_event6.type == NEIGHBOR_ADVERTISEMENT) {
      goto pass6;
    }
  }

  if (isSHOT) {
    if (eth->h_proto == htons(ETH_P_IP)) {
      icmp_event.action = DROP;
      icmp_event.saddr = ntohl(icmp_event.saddr);
      icmp_event.daddr = ntohl(icmp_event.daddr);
      icmp_ingress.perf_submit_skb(skb, skb->len, &icmp_event,
                                   sizeof(icmp_event));
    } else if (eth->h_proto == htons(ETH_P_IPV6)) {
      icmp_event6.action = DROP;
      icmp_ingress6.perf_submit_skb(skb, skb->len, &icmp_event6,
                                    sizeof(icmp_event6));
    }
    return TC_ACT_SHOT;
  }

  // Check against policy based on the information.
  struct icmp_policy_key policy_ik = {};
  bpf_probe_read_kernel_str(&policy_ik.container_id,
                            sizeof(policy_ik.container_id),
                            (void *)id_val->container_id);
  struct icmp_policy_val *policy_iv;

  if (eth->h_proto == htons(ETH_P_IP)) {
    // Check in the order of version type code remote_IP
    policy_ik.version = icmp_event.version;
    policy_ik.type = icmp_event.type;
    policy_ik.code = 0;
    policy_ik.remote_ip = 0;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass;
    }
    policy_ik.code = icmp_event.code;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass;
    }
    policy_ik.remote_ip = icmp_event.saddr;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass;
    }

    // Check in the order of version type code
    policy_ik.type = icmp_event.type;
    policy_ik.code = 0;
    policy_ik.remote_ip = 0;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass;
    }
    policy_ik.code = icmp_event.code;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass;
    }

    // Check in the order of version type remote_ip
    policy_ik.type = icmp_event.type;
    policy_ik.code = 0;
    policy_ik.remote_ip = 0;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass;
    }
    policy_ik.remote_ip = icmp_event.saddr;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass;
    }

    // Check in the order of version type
    policy_ik.type = icmp_event.type;
    policy_ik.code = 0;
    policy_ik.remote_ip = 0;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass;
    }

    // Check in the order of version remote_ip
    policy_ik.type = 0;
    policy_ik.code = 0;
    policy_ik.remote_ip = icmp_event.saddr;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass;
    }

    icmp_event.action = DROP;
    icmp_event.saddr = ntohl(icmp_event.saddr);
    icmp_event.daddr = ntohl(icmp_event.daddr);
    icmp_ingress.perf_submit_skb(skb, skb->len, &icmp_event,
                                 sizeof(icmp_event));
    return TC_ACT_SHOT;
  } else if (eth->h_proto == htons(ETH_P_IPV6)) {
    //  Check in the order of version type code remote_IP
    policy_ik.version = icmp_event6.version;
    policy_ik.type = icmp_event6.type;
    policy_ik.code = 0;
    for (int i = 0; i < IPV6_LEN; i++) {
      policy_ik.remote_ipv6[i] = 0;
    }
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass6;
    }
    policy_ik.code = icmp_event6.code;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass6;
    }
    bpf_probe_read_kernel(&policy_ik.remote_ipv6, sizeof(policy_ik.remote_ipv6),
                          &icmp_event6.saddr);
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass6;
    }

    // Check in the order of version type code
    policy_ik.type = icmp_event6.type;
    policy_ik.code = 0;
    for (int i = 0; i < IPV6_LEN; i++) {
      policy_ik.remote_ipv6[i] = 0;
    }
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass6;
    }
    policy_ik.code = icmp_event6.code;
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass6;
    }

    // Check in the order of version type remote_ip
    policy_ik.type = icmp_event6.type;
    policy_ik.code = 0;
    for (int i = 0; i < IPV6_LEN; i++) {
      policy_ik.remote_ipv6[i] = 0;
    }
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass6;
    }
    bpf_probe_read_kernel(&policy_ik.remote_ipv6, sizeof(policy_ik.remote_ipv6),
                          &icmp_event6.saddr);
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass6;
    }

    // Check in the order of version type
    policy_ik.type = icmp_event6.type;
    policy_ik.code = 0;
    for (int i = 0; i < IPV6_LEN; i++) {
      policy_ik.remote_ipv6[i] = 0;
    }
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass6;
    }

    // Check in the order of version remote_ip
    policy_ik.type = 0;
    policy_ik.code = 0;
    bpf_probe_read_kernel(&policy_ik.remote_ipv6, sizeof(policy_ik.remote_ipv6),
                          &icmp_event6.saddr);
    policy_iv = icmp_policy_list.lookup(&policy_ik);
    if (policy_iv) {
      goto pass6;
    }

    icmp_event6.action = DROP;
    icmp_ingress6.perf_submit_skb(skb, skb->len, &icmp_event6,
                                  sizeof(icmp_event6));
    return TC_ACT_SHOT;
  }

pass:
  icmp_event.action = PASS;
  icmp_event.saddr = ntohl(icmp_event.saddr);
  icmp_event.daddr = ntohl(icmp_event.daddr);
  icmp_ingress.perf_submit_skb(skb, skb->len, &icmp_event, sizeof(icmp_event));
  return TC_ACT_OK;

pass6:
  icmp_event6.action = PASS;
  icmp_ingress6.perf_submit_skb(skb, skb->len, &icmp_event6,
                                sizeof(icmp_event6));
  return TC_ACT_OK;
}
