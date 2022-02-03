# Maps
List of eBPF maps used in the program and their descriptions

| MapName     | Type   | Size | Description                                        |      Public |        Pinned|
| --------- | -------- | ------ | ------------------------------------------- | ---- |---|
| proc_ports | BPF_HASH(struct port_key, struct port_val) | 256    | Keep the process using the port |True | False|
| policy_list | BPF_HASH(struct policy_key, struct policy_val), 256 | Retain policy information | True | False |
| container_id_from_ips | BPF_HASH(struct container_ip_t, struct container_id_t), 256 | Retain correspondence between container IP and ID | True | False |