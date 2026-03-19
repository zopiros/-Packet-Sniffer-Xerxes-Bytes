#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║        Packet Sniffer — Xerxes Bytes                 ║
║     Network Traffic Analyzer using Scapy             ║
║       Educational tool — authorized use only         ║
╚══════════════════════════════════════════════════════╝

INSTALL:
  pip install scapy

USAGE (needs root/admin):
  sudo python3 sniffer.py                         # منو تعاملی
  sudo python3 sniffer.py -i eth0                 # interface مشخص
  sudo python3 sniffer.py -i eth0 -c 100          # ۱۰۰ پکت
  sudo python3 sniffer.py -i eth0 -f "tcp port 80"# فیلتر HTTP
  sudo python3 sniffer.py -i eth0 --http          # فقط HTTP
  sudo python3 sniffer.py -i eth0 --dns           # فقط DNS
  sudo python3 sniffer.py -i eth0 -o capture.pcap # ذخیره در فایل
  sudo python3 sniffer.py --analyze capture.pcap  # آنالیز فایل pcap
"""

import sys
import os
import argparse
import time
from datetime import datetime
from collections import defaultdict, Counter

# ─── بررسی نصب scapy ────────────────────────────────────────────────────────
try:
    from scapy.all import (
        sniff, wrpcap, rdpcap,
        IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        ARP, Ether, Raw,
        get_if_list, conf
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ─── رنگ‌بندی ترمینال ───────────────────────────────────────────────────────
class Color:
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
  ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
  ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
  ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
  ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
  ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
  ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
{Color.RESET}
{Color.YELLOW}           Xerxes Bytes — Packet Sniffer v1.0{Color.RESET}
{Color.CYAN}     Network Traffic Analyzer powered by Scapy{Color.RESET}
{Color.RED}  ⚠  Requires root/sudo — only on networks you own{Color.RESET}
""")


# ══════════════════════════════════════════════════════
#   بخش اول: آمار و Statistics
# ══════════════════════════════════════════════════════

class PacketStats:
    """
    نگهداری آمار پکت‌های دریافتی

    چرا defaultdict؟
    - نیازی به مقداردهی اولیه نداره
    - defaultdict(int) به جای KeyError، مقدار 0 برمیگردونه
    - defaultdict(list) به جای KeyError، لیست خالی برمیگردونه
    """
    def __init__(self):
        self.total       = 0
        self.start_time  = time.time()

        # پروتکل‌ها
        self.protocols   = Counter()

        # آدرس‌های IP
        self.src_ips     = Counter()
        self.dst_ips     = Counter()

        # پورت‌ها
        self.src_ports   = Counter()
        self.dst_ports   = Counter()

        # اندازه پکت‌ها
        self.total_bytes = 0
        self.packet_sizes= []

        # DNS queries
        self.dns_queries = []

        # HTTP requests
        self.http_requests = []

        # ARP
        self.arp_table   = {}

    def update(self, pkt):
        self.total += 1

        # اندازه پکت
        pkt_len = len(pkt)
        self.total_bytes += pkt_len
        self.packet_sizes.append(pkt_len)

        # IP layer
        if IP in pkt:
            self.src_ips[pkt[IP].src] += 1
            self.dst_ips[pkt[IP].dst] += 1

            # پروتکل
            proto = pkt[IP].proto
            if proto == 6:
                self.protocols["TCP"] += 1
            elif proto == 17:
                self.protocols["UDP"] += 1
            elif proto == 1:
                self.protocols["ICMP"] += 1
            else:
                self.protocols[f"IP/{proto}"] += 1

        # TCP/UDP پورت‌ها
        if TCP in pkt:
            self.src_ports[pkt[TCP].sport] += 1
            self.dst_ports[pkt[TCP].dport] += 1
        elif UDP in pkt:
            self.src_ports[pkt[UDP].sport] += 1
            self.dst_ports[pkt[UDP].dport] += 1

        # ARP
        if ARP in pkt:
            self.protocols["ARP"] += 1
            self.arp_table[pkt[ARP].psrc] = pkt[ARP].hwsrc

        # IPv6
        if IPv6 in pkt:
            self.protocols["IPv6"] += 1

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def pps(self) -> float:
        """packets per second"""
        e = self.elapsed()
        return self.total / e if e > 0 else 0

    def bps(self) -> float:
        """bytes per second"""
        e = self.elapsed()
        return self.total_bytes / e if e > 0 else 0

    def avg_size(self) -> float:
        return sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0


# ══════════════════════════════════════════════════════
#   بخش دوم: پردازش پکت‌ها
# ══════════════════════════════════════════════════════

# نام پورت‌های معروف
WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def port_name(port: int) -> str:
    return WELL_KNOWN_PORTS.get(port, str(port))


def format_bytes(n: int) -> str:
    """تبدیل bytes به واحد خوانا"""
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def get_tcp_flags(pkt) -> str:
    """
    خواندن TCP flags

    هر flag یه بیت در header TCP هست:
    SYN = شروع اتصال
    ACK = تأیید دریافت
    FIN = پایان اتصال
    RST = reset اتصال
    PSH = ارسال فوری داده
    URG = داده فوری
    """
    if TCP not in pkt:
        return ""
    flags = pkt[TCP].flags
    result = []
    if flags & 0x02: result.append(f"{Color.GREEN}SYN{Color.RESET}")
    if flags & 0x10: result.append(f"{Color.CYAN}ACK{Color.RESET}")
    if flags & 0x01: result.append(f"{Color.YELLOW}FIN{Color.RESET}")
    if flags & 0x04: result.append(f"{Color.RED}RST{Color.RESET}")
    if flags & 0x08: result.append(f"{Color.MAGENTA}PSH{Color.RESET}")
    if flags & 0x20: result.append("URG")
    return "[" + "|".join(result) + "]" if result else ""


def extract_dns(pkt) -> str | None:
    """
    استخراج اطلاعات DNS

    DNS پروتکلیه که hostname رو به IP تبدیل می‌کنه
    Query: مرورگر می‌پرسه «IP آدرس google.com چیه؟»
    Response: سرور DNS جواب میده «142.250.185.78»
    """
    if DNS not in pkt:
        return None

    if pkt[DNS].qr == 0:  # Query
        if DNSQR in pkt:
            qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            return f"DNS Query  → {Color.YELLOW}{qname}{Color.RESET}"

    else:  # Response
        if DNSRR in pkt:
            qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.') if pkt[DNS].qd else "?"
            answers = []
            ans = pkt[DNS].an
            while ans:
                try:
                    if hasattr(ans, 'rdata'):
                        answers.append(str(ans.rdata))
                except Exception:
                    pass
                ans = ans.payload if hasattr(ans, 'payload') else None
                if not hasattr(ans, 'rdata'):
                    break
            answer_str = ", ".join(answers[:3]) if answers else "?"
            return f"DNS Reply  ← {Color.GREEN}{qname}{Color.RESET} = {answer_str}"

    return None


def extract_http(pkt) -> str | None:
    """
    استخراج اطلاعات HTTP

    HTTP روی TCP پورت ۸۰ کار می‌کنه
    مرورگر: GET /index.html HTTP/1.1
    سرور:   HTTP/1.1 200 OK

    نکته: HTTPS رمزگذاری شده‌ست و نمی‌شه خوند
    این فقط برای HTTP ساده کار می‌کنه
    """
    try:
        if HTTPRequest in pkt:
            method = pkt[HTTPRequest].Method.decode('utf-8', errors='ignore')
            host   = pkt[HTTPRequest].Host.decode('utf-8', errors='ignore') if pkt[HTTPRequest].Host else "?"
            path   = pkt[HTTPRequest].Path.decode('utf-8', errors='ignore') if pkt[HTTPRequest].Path else "/"
            return f"HTTP  {Color.GREEN}{method}{Color.RESET} http://{host}{path[:60]}"

        if HTTPResponse in pkt:
            status = pkt[HTTPResponse].Status_Code.decode('utf-8', errors='ignore') if hasattr(pkt[HTTPResponse], 'Status_Code') else "?"
            return f"HTTP  Response {Color.CYAN}{status}{Color.RESET}"
    except Exception:
        pass

    # fallback: خوندن Raw payload برای HTTP
    if Raw in pkt and TCP in pkt:
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                lines  = payload.split('\n')
                first  = lines[0].strip()[:80]
                host   = ""
                for line in lines[1:5]:
                    if line.lower().startswith('host:'):
                        host = line.split(':', 1)[1].strip()
                        break
                return f"HTTP  {Color.GREEN}{first}{Color.RESET}  host={host}"
            elif payload.startswith('HTTP/'):
                first = payload.split('\n')[0].strip()[:60]
                return f"HTTP  {Color.CYAN}{first}{Color.RESET}"
        except Exception:
            pass

    return None


def extract_arp(pkt) -> str | None:
    """
    استخراج اطلاعات ARP

    ARP پروتکلیه که IP رو به MAC تبدیل می‌کنه
    «کی IP آدرس 192.168.1.1 رو داره؟»
    «من! MAC آدرسم aa:bb:cc:dd:ee:ff هست»

    ARP Spoofing = ارسال پیام‌های جعلی ARP برای redirect ترافیک
    """
    if ARP not in pkt:
        return None
    op = "Who has" if pkt[ARP].op == 1 else "Is at"
    if pkt[ARP].op == 1:
        return (f"ARP  {Color.YELLOW}Who has{Color.RESET} "
                f"{pkt[ARP].pdst}? Tell {pkt[ARP].psrc}")
    else:
        return (f"ARP  {Color.GREEN}{pkt[ARP].psrc}{Color.RESET} "
                f"is at {Color.CYAN}{pkt[ARP].hwsrc}{Color.RESET}")


# ══════════════════════════════════════════════════════
#   بخش سوم: نمایش پکت‌ها
# ══════════════════════════════════════════════════════

packet_counter = 0


def process_packet(pkt, stats: PacketStats, show_dns=True,
                   show_http=True, show_arp=True,
                   show_raw=False, dns_only=False,
                   http_only=False, verbose=False):
    """
    پردازش و نمایش هر پکت

    لایه‌های شبکه (OSI Model):
    Layer 2 (Data Link): Ethernet — MAC addresses
    Layer 3 (Network):   IP        — IP addresses
    Layer 4 (Transport): TCP/UDP   — Ports
    Layer 7 (Application): HTTP, DNS, ...
    """
    global packet_counter
    packet_counter += 1
    stats.update(pkt)

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    num       = f"{Color.DIM}#{packet_counter:>5}{Color.RESET}"

    # ─── DNS ────────────────────────────────────────────────────────────────
    dns_info = extract_dns(pkt)
    if dns_info:
        if DNS in pkt and DNSQR in pkt:
            stats.dns_queries.append(
                pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            )
        if show_dns or dns_only:
            src = pkt[IP].src if IP in pkt else "?"
            print(f"  {num} {Color.DIM}{timestamp}{Color.RESET}  "
                  f"{Color.MAGENTA}{'DNS':<6}{Color.RESET}  "
                  f"{Color.DIM}{src:<16}{Color.RESET}  {dns_info}")
        return

    if dns_only:
        return

    # ─── HTTP ────────────────────────────────────────────────────────────────
    http_info = extract_http(pkt)
    if http_info:
        stats.http_requests.append(http_info)
        if show_http or http_only:
            src = pkt[IP].src if IP in pkt else "?"
            dst = pkt[IP].dst if IP in pkt else "?"
            print(f"  {num} {Color.DIM}{timestamp}{Color.RESET}  "
                  f"{Color.BLUE}{'HTTP':<6}{Color.RESET}  "
                  f"{Color.DIM}{src:<16} → {dst:<16}{Color.RESET}  {http_info}")
        return

    if http_only:
        return

    # ─── ARP ─────────────────────────────────────────────────────────────────
    arp_info = extract_arp(pkt)
    if arp_info and show_arp:
        print(f"  {num} {Color.DIM}{timestamp}{Color.RESET}  "
              f"{Color.YELLOW}{'ARP':<6}{Color.RESET}  "
              f"{'':16}  {arp_info}")
        return

    # ─── IP پکت‌ها ────────────────────────────────────────────────────────────
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl    = pkt[IP].ttl
        size   = len(pkt)

        # TCP
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = get_tcp_flags(pkt)
            sname = port_name(sport)
            dname = port_name(dport)

            color = Color.GREEN
            if dport in (80, 8080):
                color = Color.BLUE
            elif dport == 443:
                color = Color.CYAN
            elif dport == 22:
                color = Color.YELLOW
            elif dport in (3306, 5432, 27017):
                color = Color.MAGENTA

            line = (f"  {num} {Color.DIM}{timestamp}{Color.RESET}  "
                    f"{color}{'TCP':<6}{Color.RESET}  "
                    f"{src_ip:<16} → {dst_ip:<16}  "
                    f"{Color.DIM}{sname}:{sport} → {dname}:{dport}{Color.RESET}  "
                    f"{flags}  {Color.DIM}{size}B{Color.RESET}")

            if verbose:
                line += f"  TTL={ttl}"
            print(line)

        # UDP
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            sname = port_name(sport)
            dname = port_name(dport)

            print(f"  {num} {Color.DIM}{timestamp}{Color.RESET}  "
                  f"{Color.CYAN}{'UDP':<6}{Color.RESET}  "
                  f"{src_ip:<16} → {dst_ip:<16}  "
                  f"{Color.DIM}{sname}:{sport} → {dname}:{dport}{Color.RESET}  "
                  f"{Color.DIM}{size}B{Color.RESET}")

        # ICMP
        elif ICMP in pkt:
            icmp_type = pkt[ICMP].type
            type_name = {0: "Echo Reply", 8: "Echo Request",
                         3: "Dest Unreachable", 11: "TTL Exceeded"}.get(icmp_type, str(icmp_type))

            print(f"  {num} {Color.DIM}{timestamp}{Color.RESET}  "
                  f"{Color.RED}{'ICMP':<6}{Color.RESET}  "
                  f"{src_ip:<16} → {dst_ip:<16}  "
                  f"{Color.YELLOW}{type_name}{Color.RESET}  "
                  f"{Color.DIM}{size}B{Color.RESET}")

        else:
            proto = pkt[IP].proto
            print(f"  {num} {Color.DIM}{timestamp}{Color.RESET}  "
                  f"{'IP':<6}  {src_ip:<16} → {dst_ip:<16}  "
                  f"proto={proto}  {Color.DIM}{size}B{Color.RESET}")


# ══════════════════════════════════════════════════════
#   بخش چهارم: نمایش آمار نهایی
# ══════════════════════════════════════════════════════

def print_summary(stats: PacketStats):
    """نمایش خلاصه آماری کامل"""

    print(f"\n\n{'═'*60}")
    print(f"{Color.BOLD}  CAPTURE SUMMARY{Color.RESET}")
    print(f"{'═'*60}\n")

    elapsed = stats.elapsed()

    # ─── کلیات ───────────────────────────────────────────────────────────────
    print(f"  {Color.BOLD}General:{Color.RESET}")
    print(f"    Total packets : {Color.GREEN}{stats.total:,}{Color.RESET}")
    print(f"    Total bytes   : {Color.GREEN}{format_bytes(stats.total_bytes)}{Color.RESET}")
    print(f"    Duration      : {elapsed:.1f}s")
    print(f"    Avg speed     : {Color.CYAN}{stats.pps():.1f} pkt/s  |  "
          f"{format_bytes(int(stats.bps()))}/s{Color.RESET}")
    print(f"    Avg pkt size  : {stats.avg_size():.0f} bytes")

    # ─── پروتکل‌ها ────────────────────────────────────────────────────────────
    if stats.protocols:
        print(f"\n  {Color.BOLD}Protocols:{Color.RESET}")
        total = sum(stats.protocols.values())
        for proto, count in stats.protocols.most_common():
            pct = (count / total * 100) if total > 0 else 0
            bar = "█" * int(pct / 3)
            print(f"    {Color.CYAN}{proto:<10}{Color.RESET} "
                  f"{count:>6,}  {Color.DIM}{bar:<20}{Color.RESET}  {pct:.1f}%")

    # ─── Top IPs ──────────────────────────────────────────────────────────────
    if stats.src_ips:
        print(f"\n  {Color.BOLD}Top Source IPs:{Color.RESET}")
        for ip, count in stats.src_ips.most_common(5):
            print(f"    {Color.GREEN}{ip:<20}{Color.RESET} {count:>6,} packets")

    if stats.dst_ips:
        print(f"\n  {Color.BOLD}Top Destination IPs:{Color.RESET}")
        for ip, count in stats.dst_ips.most_common(5):
            print(f"    {Color.YELLOW}{ip:<20}{Color.RESET} {count:>6,} packets")

    # ─── Top Ports ────────────────────────────────────────────────────────────
    if stats.dst_ports:
        print(f"\n  {Color.BOLD}Top Destination Ports:{Color.RESET}")
        for port, count in stats.dst_ports.most_common(5):
            name = WELL_KNOWN_PORTS.get(port, "")
            print(f"    {Color.MAGENTA}{port:<8}{Color.RESET}"
                  f"{Color.DIM}{name:<12}{Color.RESET} {count:>6,} packets")

    # ─── DNS Queries ──────────────────────────────────────────────────────────
    if stats.dns_queries:
        unique_dns = list(dict.fromkeys(stats.dns_queries))[:10]
        print(f"\n  {Color.BOLD}DNS Queries ({len(stats.dns_queries)} total):{Color.RESET}")
        for q in unique_dns:
            print(f"    {Color.YELLOW}→{Color.RESET} {q}")

    # ─── HTTP Requests ────────────────────────────────────────────────────────
    if stats.http_requests:
        print(f"\n  {Color.BOLD}HTTP Requests ({len(stats.http_requests)} total):{Color.RESET}")
        for req in stats.http_requests[:5]:
            clean = req.replace(Color.GREEN, "").replace(Color.RESET, "")
            print(f"    {Color.BLUE}→{Color.RESET} {clean[:70]}")

    # ─── ARP Table ────────────────────────────────────────────────────────────
    if stats.arp_table:
        print(f"\n  {Color.BOLD}ARP Table (IP → MAC):{Color.RESET}")
        for ip, mac in list(stats.arp_table.items())[:10]:
            print(f"    {Color.GREEN}{ip:<18}{Color.RESET} → "
                  f"{Color.CYAN}{mac}{Color.RESET}")

    print(f"\n{'═'*60}\n")


# ══════════════════════════════════════════════════════
#   بخش پنجم: آنالیز فایل PCAP
# ══════════════════════════════════════════════════════

def analyze_pcap(filepath: str):
    """
    آنالیز فایل pcap ذخیره‌شده

    فایل pcap فرمت استانداردیه که Wireshark هم استفاده می‌کنه
    بعد از capture، می‌تونی فایل رو در Wireshark باز کنی
    """
    if not os.path.exists(filepath):
        print(f"\n  {Color.RED}[!] File not found: {filepath}{Color.RESET}")
        return

    print(f"\n  {Color.CYAN}[*] Loading: {filepath}{Color.RESET}")

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"  {Color.RED}[!] Error reading pcap: {e}{Color.RESET}")
        return

    print(f"  {Color.GREEN}[+] Loaded {len(packets)} packets{Color.RESET}\n")

    stats = PacketStats()

    print(f"  {Color.BOLD}{'#':<6} {'TIME':<14} {'PROTO':<8} "
          f"{'SRC':<18} {'DST':<18} {'INFO'}{Color.RESET}")
    print(f"  {'─'*80}")

    for i, pkt in enumerate(packets, 1):
        process_packet(pkt, stats, verbose=False)

    print_summary(stats)


# ══════════════════════════════════════════════════════
#   بخش ششم: interface‌ها
# ══════════════════════════════════════════════════════

def list_interfaces():
    """نمایش interface‌های شبکه موجود"""
    print(f"\n  {Color.BOLD}Available network interfaces:{Color.RESET}\n")
    try:
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces, 1):
            print(f"    {Color.GREEN}{i}.{Color.RESET} {iface}")
    except Exception:
        print(f"  {Color.RED}Could not list interfaces. Try manually.{Color.RESET}")
    print()


# ══════════════════════════════════════════════════════
#   بخش هفتم: منو تعاملی
# ══════════════════════════════════════════════════════

def run_sniffer(interface, count, bpf_filter, output_file,
                dns_only, http_only, show_dns, show_http,
                show_arp, verbose, stats):
    """اجرای sniffer"""

    header = (f"  {Color.BOLD}{'#':<6} {'TIME':<14} {'PROTO':<8} "
              f"{'SRC':<18} {'DST':<18} {'INFO'}{Color.RESET}")
    separator = f"  {'─'*80}"

    print(header)
    print(separator)

    captured_packets = []

    def handler(pkt):
        captured_packets.append(pkt)
        process_packet(
            pkt, stats,
            show_dns=show_dns, show_http=show_http,
            show_arp=show_arp, dns_only=dns_only,
            http_only=http_only, verbose=verbose
        )

    sniff_kwargs = {
        "prn":   handler,
        "store": False,
        "iface": interface,
    }

    if count > 0:
        sniff_kwargs["count"] = count
    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter

    print(f"\n  {Color.CYAN}[*] Sniffing on {interface or 'default'}  "
          f"filter={bpf_filter or 'none'}  "
          f"count={count or '∞'}{Color.RESET}")
    print(f"  {Color.YELLOW}[*] Press Ctrl+C to stop\n{Color.RESET}")

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print(f"\n\n  {Color.YELLOW}[!] Stopped by user{Color.RESET}")
    except PermissionError:
        print(f"\n  {Color.RED}[!] Permission denied — run with sudo/root{Color.RESET}")
        return []
    except Exception as e:
        print(f"\n  {Color.RED}[!] Error: {e}{Color.RESET}")
        return []

    if output_file and captured_packets:
        try:
            wrpcap(output_file, captured_packets)
            print(f"  {Color.GREEN}[+] Saved {len(captured_packets)} packets → {output_file}{Color.RESET}")
            print(f"  {Color.CYAN}[*] Open with: wireshark {output_file}{Color.RESET}")
        except Exception as e:
            print(f"  {Color.RED}[!] Could not save: {e}{Color.RESET}")

    return captured_packets


def interactive_mode():
    """منو تعاملی"""

    print(f"\n{Color.CYAN}{'─'*50}{Color.RESET}")
    print(f"{Color.BOLD}  PACKET SNIFFER — Setup{Color.RESET}")
    print(f"{Color.CYAN}{'─'*50}{Color.RESET}\n")

    # نمایش interface‌ها
    list_interfaces()

    interface = input("  Interface (Enter for default): ").strip() or None

    print(f"\n  {Color.BOLD}Mode:{Color.RESET}")
    print(f"  {Color.GREEN}1{Color.RESET}  All traffic")
    print(f"  {Color.CYAN}2{Color.RESET}  DNS only")
    print(f"  {Color.BLUE}3{Color.RESET}  HTTP only")
    print(f"  {Color.YELLOW}4{Color.RESET}  Custom BPF filter")
    mode = input("\n  Choice [1]: ").strip() or "1"

    dns_only   = mode == "2"
    http_only  = mode == "3"
    bpf_filter = None

    if mode == "4":
        print(f"  {Color.DIM}Examples: tcp port 80  |  host 192.168.1.1  |  icmp{Color.RESET}")
        bpf_filter = input("  BPF filter: ").strip() or None
    elif mode == "3":
        bpf_filter = "tcp port 80 or tcp port 8080"

    try:
        count_in = input("\n  Packet count (0 = unlimited): ").strip()
        count = int(count_in) if count_in else 0
    except ValueError:
        count = 0

    output = input("  Save to file (.pcap, Enter to skip): ").strip() or None

    stats = PacketStats()
    print()

    run_sniffer(
        interface=interface, count=count,
        bpf_filter=bpf_filter, output_file=output,
        dns_only=dns_only, http_only=http_only,
        show_dns=True, show_http=True, show_arp=True,
        verbose=False, stats=stats
    )

    print_summary(stats)


def main():
    banner()

    if not SCAPY_AVAILABLE:
        print(f"  {Color.RED}[!] Scapy not installed!{Color.RESET}")
        print(f"  {Color.YELLOW}Run: pip install scapy{Color.RESET}\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Packet Sniffer — Xerxes Bytes"
    )
    parser.add_argument("-i", "--interface", type=str, help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("-c", "--count",     type=int, default=0, help="Packets to capture (0=unlimited)")
    parser.add_argument("-f", "--filter",    type=str, help="BPF filter (e.g. 'tcp port 80')")
    parser.add_argument("-o", "--output",    type=str, help="Save capture to .pcap file")
    parser.add_argument("--analyze",         type=str, help="Analyze existing .pcap file")
    parser.add_argument("--dns",    action="store_true", help="Show DNS only")
    parser.add_argument("--http",   action="store_true", help="Show HTTP only")
    parser.add_argument("--no-arp", action="store_true", help="Hide ARP packets")
    parser.add_argument("--list",   action="store_true", help="List network interfaces")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    if args.analyze:
        analyze_pcap(args.analyze)
        return

    if args.interface or args.filter or args.count or args.output or args.dns or args.http:
        stats = PacketStats()
        run_sniffer(
            interface  = args.interface,
            count      = args.count,
            bpf_filter = "tcp port 80 or tcp port 8080" if args.http else args.filter,
            output_file= args.output,
            dns_only   = args.dns,
            http_only  = args.http,
            show_dns   = True,
            show_http  = True,
            show_arp   = not args.no_arp,
            verbose    = args.verbose,
            stats      = stats
        )
        print_summary(stats)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
