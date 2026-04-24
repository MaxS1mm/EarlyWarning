import time
import threading
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
from .port_scan_detector import PortScanDetector
from .firewall import Firewall


class FlowMonitor:
    def __init__(self, alert_callback=None, log_file="ids_log.txt"):
        self.connections = {}
        self.lock = threading.Lock()
        self.sniffer = None
        self.TIMEOUT = 60

        self.portscan = PortScanDetector()
        self.firewall = Firewall()
        self.alert_callback = alert_callback
        self.log_file = log_file

    # ---------------- LOGGING ---------------- #

    def log_alert(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

    # ---------------- CONNECTION TRACKING ---------------- #

    def _normalize_key(self, proto, src, sport, dst, dport):
        if (src, sport) < (dst, dport):
            return (proto, src, sport, dst, dport)
        return (proto, dst, dport, src, sport)

    def _handle_packet(self, pkt):
        if IP not in pkt:
            return

        ip = pkt[IP]
        now = time.time()

        if TCP in pkt:
            proto = "TCP"
            l4 = pkt[TCP]
        elif UDP in pkt:
            proto = "UDP"
            l4 = pkt[UDP]
        elif ICMP in pkt:
            proto = "ICMP"
            l4 = pkt[ICMP]
        else:
            return

        src_port = getattr(l4, "sport", 0)
        dst_port = getattr(l4, "dport", 0)

        # ---------------- FIREWALL CHECK ---------------- #
        action, matched_rule = self.firewall.check_packet(
            proto, ip.src, ip.dst, src_port, dst_port
        )

        if action == "deny":
            msg = (f"FIREWALL BLOCKED {proto} {ip.src}:{src_port} "
                   f"-> {ip.dst}:{dst_port}")
            self.log_alert(msg)
            if self.alert_callback:
                self.alert_callback(ip.src, {"type": "firewall_block",
                                             "rule": matched_rule})
            return  # drop the packet — don't track it

        if action == "alert":
            msg = (f"FIREWALL ALERT {proto} {ip.src}:{src_port} "
                   f"-> {ip.dst}:{dst_port}")
            self.log_alert(msg)
            if self.alert_callback:
                self.alert_callback(ip.src, {"type": "firewall_alert",
                                             "rule": matched_rule})

        # ---------------- CONNECTION TABLE ---------------- #
        key = self._normalize_key(proto, ip.src, src_port, ip.dst, dst_port)

        with self.lock:
            if key not in self.connections:
                self.connections[key] = {
                    "packets": 0,
                    "bytes": 0,
                    "last_seen": now,
                    "state": "ACTIVE"
                }

            self.connections[key]["packets"] += 1
            self.connections[key]["bytes"] += len(pkt)
            self.connections[key]["last_seen"] = now

            if proto == "TCP":
                flags = l4.flags
                if flags & 0x02:
                    self.connections[key]["state"] = "SYN"
                elif flags & 0x01:
                    self.connections[key]["state"] = "FIN"
                elif flags & 0x04:
                    self.connections[key]["state"] = "RST"
                else:
                    self.connections[key]["state"] = "EST"

        # ---------------- PORT SCAN DETECTION ---------------- #
        if proto == "TCP":
            flags = int(l4.flags)
            fin = bool(flags & 0x01)
            syn = bool(flags & 0x02)
            rst = bool(flags & 0x04)
            psh = bool(flags & 0x08)
            urg = bool(flags & 0x20)

            scan_type = None

            if syn and not fin and not rst:
                # SYN-only — classic stealth scan
                scan_type = "SYN"
            elif fin and not syn and not rst and not psh and not urg:
                # FIN scan
                scan_type = "FIN"
            elif flags == 0:
                # NULL scan — no flags at all
                scan_type = "NULL"
            elif fin and psh and urg and not syn:
                # XMAS scan
                scan_type = "XMAS"

            if scan_type:
                is_scan, detail = self.portscan.process_packet(
                    ip.src, dst_port, now, scan_type
                )
                if is_scan:
                    msg = (f"PORT SCAN detected from {ip.src} | "
                           f"Type: {detail['scan_type']} | "
                           f"Ports probed: {detail['total_ports']}")

                    self.log_alert(msg)
                    if self.alert_callback:
                        self.alert_callback(ip.src, detail)

        elif proto == "UDP":
            is_scan, detail = self.portscan.process_packet(
                ip.src, dst_port, now, "UDP"
            )
            if is_scan:
                msg = (f"UDP SCAN detected from {ip.src} | "
                       f"Ports probed: {detail['total_ports']}")

                self.log_alert(msg)
                if self.alert_callback:
                    self.alert_callback(ip.src, detail)

    # ---------------- SNIFFER CONTROL ---------------- #

    def start(self, iface=None):
        self.sniffer = AsyncSniffer(prn=self._handle_packet, store=False)
        self.sniffer.start()

    def stop(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()

    # ---------------- CONNECTION VIEW ---------------- #

    def get_active_connections(self):
        now = time.time()
        active = []

        with self.lock:
            for key in list(self.connections.keys()):
                data = self.connections[key]
                if now - data["last_seen"] > self.TIMEOUT:
                    del self.connections[key]
                    continue
                active.append((key, data))

        return active
