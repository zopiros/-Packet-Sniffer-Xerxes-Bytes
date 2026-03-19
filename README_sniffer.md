# 📡 Packet Sniffer — Xerxes Bytes

> A network traffic analyzer built with Python and Scapy. Captures, parses, and displays live network packets with protocol-aware filtering and real-time statistics.

Built and developed by **[Xerxes Bytes](https://github.com/zopiros)** — a student-driven cybersecurity group focused on scripting, vulnerability analysis, and hands-on security research.

---

## ⚡ Features

- **Live packet capture** on any network interface
- **Protocol parsing** — TCP, UDP, ICMP, DNS, HTTP, ARP, IPv6
- **DNS monitoring** — see every hostname your machine resolves
- **HTTP inspection** — capture unencrypted HTTP requests and responses
- **ARP table** — map IP addresses to MAC addresses
- **BPF filters** — standard Berkeley Packet Filter syntax (same as Wireshark/tcpdump)
- **PCAP export** — save captures and open in Wireshark
- **PCAP analysis** — analyze previously captured files
- **Real-time stats** — packets/sec, bytes/sec, top IPs, top ports
- **TCP flags** — SYN, ACK, FIN, RST, PSH detection

---

## 🛠️ Requirements

```bash
pip install scapy
```

> ⚠️ Requires **root/sudo** — packet capture needs raw socket access.

---

## 🚀 Usage

### Interactive menu
```bash
sudo python3 sniffer.py
```

### Capture on a specific interface
```bash
sudo python3 sniffer.py -i eth0
sudo python3 sniffer.py -i wlan0
```

### Capture with packet limit
```bash
sudo python3 sniffer.py -i eth0 -c 100
```

### Filter by protocol or port (BPF syntax)
```bash
sudo python3 sniffer.py -i eth0 -f "tcp port 80"
sudo python3 sniffer.py -i eth0 -f "host 192.168.1.1"
sudo python3 sniffer.py -i eth0 -f "icmp"
sudo python3 sniffer.py -i eth0 -f "not port 22"
```

### Monitor DNS queries only
```bash
sudo python3 sniffer.py -i eth0 --dns
```

### Monitor HTTP traffic only
```bash
sudo python3 sniffer.py -i eth0 --http
```

### Save capture to file
```bash
sudo python3 sniffer.py -i eth0 -c 500 -o capture.pcap
wireshark capture.pcap   # open in Wireshark
```

### Analyze saved pcap file
```bash
sudo python3 sniffer.py --analyze capture.pcap
```

### List available interfaces
```bash
sudo python3 sniffer.py --list
```

---

## 📋 Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-i`, `--interface` | Network interface (eth0, wlan0...) | system default |
| `-c`, `--count` | Number of packets to capture | unlimited |
| `-f`, `--filter` | BPF filter expression | none |
| `-o`, `--output` | Save to .pcap file | — |
| `--analyze` | Analyze existing .pcap file | — |
| `--dns` | Show DNS packets only | — |
| `--http` | Show HTTP packets only | — |
| `--no-arp` | Hide ARP packets | — |
| `--list` | List network interfaces | — |
| `-v`, `--verbose` | Verbose output (show TTL, etc.) | — |

---

## 📸 Example Output

```
  #      TIME           PROTO    SRC                DST                INFO
  ────────────────────────────────────────────────────────────────────────────────
  #    1 14:23:01.442   TCP      192.168.1.5        142.250.185.78     http:443 → https:443  [SYN]  74B
  #    2 14:23:01.443   TCP      142.250.185.78     192.168.1.5        https:443 → http:443  [SYN|ACK]  74B
  #    3 14:23:01.501   DNS      192.168.1.5        8.8.8.8            DNS Query  → github.com
  #    4 14:23:01.523   DNS      8.8.8.8            192.168.1.5        DNS Reply  ← github.com = 140.82.113.4
  #    5 14:23:01.601   HTTP     192.168.1.5        93.184.216.34      HTTP  GET http://example.com/index.html
  #    6 14:23:01.701   ARP      192.168.1.1        —                  ARP  Who has 192.168.1.5? Tell 192.168.1.1
  #    7 14:23:01.702   ICMP     192.168.1.5        8.8.8.8            Echo Request  74B
```

### Summary
```
══════════════════════════════════════════════════════════════
  CAPTURE SUMMARY
══════════════════════════════════════════════════════════════

  General:
    Total packets : 1,247
    Total bytes   : 843.2 KB
    Duration      : 30.4s
    Avg speed     : 41.0 pkt/s  |  27.7 KB/s
    Avg pkt size  : 674 bytes

  Protocols:
    TCP        892    ████████████████████  71.5%
    UDP        198    ████                  15.9%
    DNS        134    ███                   10.7%
    ICMP        23    ░                      1.8%

  Top Source IPs:
    192.168.1.5          892 packets
    192.168.1.1          201 packets

  DNS Queries (134 total):
    → github.com
    → api.github.com
    → fonts.googleapis.com
```

---

## 🧠 How It Works

### OSI Model — What We're Capturing

```
Layer 7  Application  HTTP, DNS, FTP, SSH
Layer 4  Transport    TCP, UDP
Layer 3  Network      IP (routing between networks)
Layer 2  Data Link    Ethernet (MAC addresses, ARP)
```

Scapy captures at **Layer 2** (raw Ethernet frames) and lets us dissect every layer upward.

### How Scapy Sniffs
```python
from scapy.all import sniff

def handler(packet):
    if IP in packet:
        print(packet[IP].src, "→", packet[IP].dst)

sniff(iface="eth0", prn=handler, count=100)
```

### BPF Filters
Berkeley Packet Filter runs **in the kernel** — packets are filtered before reaching Python, making it very efficient.

```bash
tcp port 80          # only TCP on port 80
host 192.168.1.1     # only traffic to/from this IP
not port 22          # exclude SSH
icmp                 # only ICMP (ping)
tcp and port 443     # HTTPS only
```

### TCP Flags — The 3-Way Handshake
```
Client  →  SYN        →  Server   (I want to connect)
Client  ←  SYN+ACK    ←  Server   (OK, I acknowledge)
Client  →  ACK        →  Server   (Connection established)
...data exchange...
Client  →  FIN        →  Server   (I'm done)
```

### Why Can't We See HTTPS?
HTTPS encrypts data at Layer 7 using TLS. The packet headers (IP, TCP) are still visible, but the **payload is encrypted**. That's why this tool only shows HTTP (port 80), not HTTPS (port 443).

---

## 🎯 Recommended Practice Environments

- **Your own home network** — monitor your own traffic
- **TryHackMe** — network analysis rooms
- **Wireshark** — open the saved `.pcap` files for deeper analysis
- **Virtual Machine** — create an isolated test network

---

## ⚠️ Legal Disclaimer

Packet sniffing on networks you don't own or without explicit permission is **illegal** in most countries.  
This tool is for **educational purposes** and **authorized testing only**.  
Always use on your own devices or networks you have permission to analyze.

---

## 👥 About Xerxes Bytes

**Xerxes Bytes** is a student cybersecurity group exploring offensive and defensive security through hands-on projects. We build open-source tools to learn scripting, penetration testing techniques, and vulnerability research in controlled environments.

🔗 GitHub: [github.com/zopiros](https://github.com/zopiros)

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.
