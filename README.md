# P4 Intrusion Detection System (IDS) with BMv2

A **P4-programmable switch** that detects and blocks **TCP SYN flood attacks** targeting web servers (port 80) using a **blacklist of malicious source IPs**.

Built with:
- **P4_16** program
- **BMv2** (`simple_switch_grpc`)
- **Mininet** + **p4utils**
- **P4Runtime** for dynamic rule insertion

---

## Features

- Parses Ethernet → IPv4 → TCP headers
- Detects **SYN packets** to **port 80**
- **Drops** packets from blacklisted IPs
- Forwards legitimate traffic
- Dynamic rules via **P4Runtime**
- Tested in **Mininet** with `hping3` and `tcpdump`

---

## Topology

```
h1 (192.168.1.1)  ----  s1 (P4 Switch)  ----  h2 (192.168.1.2)
   Attacker                     IDS                     Web Server
```

- `h1` sends SYN flood → **blocked**
- Normal traffic → **forwarded**

---

## Prerequisites

- Ubuntu 20.04/22.04 (tested)
- `sudo` access
- Internet connection

---

## Quick Start (One-Click)

```bash
# Clone repo
git clone https://github.com/leksnation/p4-ids-bmv2.git
cd p4-ids-bmv2

```
---

## Manual Setup

### 1. Install Dependencies

```bash
# BMv2 (P4 switch)
cd ~
git clone --recursive https://github.com/p4lang/behavioral-model.git
cd behavioral-model
./install_deps.sh
./autogen.sh
./configure --with-proto
make -j$(nproc)
sudo make install
sudo ldconfig

# p4c (P4 compiler)
cd ~
git clone --recursive https://github.com/p4lang/p4c.git
cd p4c
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
sudo ldconfig

# p4utils (Mininet helper)
pip3 install p4utils p4runtime
```

---

### 2. Compile P4 Program

```bash
cd p4-ids-bmv2
p4c \
  --p4runtime-files simple_switch.p4info.txtpb \
  --p4runtime-format text \
  simple_switch.p4 \
  -o simple_switch.json
```

---

### 3. Start P4 Switch

```bash
sudo simple_switch_grpc \
  -i 1@h1-eth0 -i 2@h2-eth0 \
  --log-console \
  simple_switch.json
```

> Leave running in **Terminal 1**

---

### 4. Start Mininet

```bash
sudo python3 topo.py
```

> Run in **Terminal 2**

---

### 5. Insert IDS Rule

```bash
p4runtime-sh --device-id 1 \
  --election-id 1 \
  --config simple_switch.p4info.txtpb,simple_switch.json
```

Inside the shell:
```python
te = p4rt.TableEntry("IngressImpl.bad_sources")
te.match["hdr.ipv4.src_addr"] = "192.168.1.1"
te.match["hdr.tcp.dst_port"] = "80"
te.action = "IngressImpl.drop"
te.insert()
exit()
```

---

### 6. Test the IDS

In Mininet CLI:

```bash
mininet> h1 ping h2
# Works

mininet> h1 hping3 -S -p 80 192.168.1.2 -c 5
# Sends SYN flood

mininet> h2 tcpdump -i h2-eth0 port 80 -c 5
# 0 packets → BLOCKED!
```

---

## Files

| File | Description |
|------|-------------|
| `simple_switch.p4` | P4_16 IDS program |
| `simple_switch.json` | Compiled BMv2 config |
| `simple_switch.p4info.txtpb` | P4Runtime metadata |
| `topo.py` | Mininet topology with `p4utils` |
| `setup_and_run.sh` | Full auto-install + run script |
| `README.md` | This file |

---

## Extending the IDS

### Add Rate Limiting (Future)
```p4
register<bit<32>>(1024) syn_count;
```
→ Count SYNs per IP, drop if > threshold.

### Mirror Bad Packets
```p4
action mirror_to_collector() {
    clone3(CloneType.I2E, 100, {});
}
```

---

## Troubleshooting

| Error | Fix |
|------|-----|
| `simple_switch_grpc: command not found` | Run `sudo make install` in `behavioral-model` |
| `p4c: command not found` | Install `p4c` from source |
| `h1-eth0: no such device` | Run `simple_switch_grpc` **before** `topo.py` |
| Packets not dropped | Check rule: `p4runtime-sh` → `table_read` |

---

## Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feature/rate-limit`
3. Commit: `git commit -m "Add rate limiting"`
4. Push: `git push origin feature/rate-limit`
5. Open a Pull Request

---

## License

[MIT License](LICENSE)

---

## Acknowledgments

- [P4.org](https://p4.org)
- [BMv2](https://github.com/p4lang/behavioral-model)
- [p4utils](https://github.com/nsg-ethz/p4-utils)

---

**Star this repo if you found it helpful!**

--- 

*Built with love for programmable networks.*
