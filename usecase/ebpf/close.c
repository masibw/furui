#include <bcc/proto.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <net/inet_sock.h>
#include <net/sock.h>

BPF_PERF_OUTPUT(close_events);

TRACEPOINT_PROBE(sched, sched_process_exit) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  struct pid_namespace *pidns =
      (struct pid_namespace *)task->nsproxy->pid_ns_for_children;

  // check whether this process running in container (another namespace). 0=host
  if (pidns->level == 0) {
    return 0;
  }

  u32 pid = bpf_get_current_pid_tgid();

  close_events.perf_submit(args, &pid, sizeof(pid));
  return 0;
}