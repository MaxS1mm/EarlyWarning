import time
import threading
import scapy.all as scapy
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
from .port_scan_detector import PortScanDetector
from .firewall import Firewall


class FlowMonitor:
    def __init__(self, alert_callback=None):
        self.connections = {}
        self.lock = threading.Lock()
        self.sniffer = None
        self.TIMEOUT = 60

        self.portscan = PortScanDetector()
        self.firewall = Firewall()
        self.alert_callback = alert_callback

        self.local_ip = None
        # IPs we have sent traffic to — responses from these IPs
        # are expected and should not trigger scan detection.
        self.outbound_targets = set()

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
            if self.alert_callback:
                self.alert_callback(ip.src, {"type": "firewall_block",
                                             "rule": matched_rule})
            return  # drop the packet — don't track it

        if action == "alert":
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

        # ---------------- OUTBOUND TRACKING ---------------- #
        # If this packet is from us going out, remember the destination
        # so we don't flag their response traffic as a port scan.
        is_unsolicited = True
        if self.local_ip and ip.src == self.local_ip:
            self.outbound_targets.add(ip.dst)
            is_unsolicited = False
        elif ip.src in self.outbound_targets:
            is_unsolicited = False

        # ---------------- PORT SCAN DETECTION ---------------- #
        # Only check for scans on unsolicited inbound traffic —
        # responses from servers we contacted are normal.
        if not is_unsolicited:
            return
        if proto == "TCP":
            flags = int(l4.flags)
            fin = bool(flags & 0x01)
            syn = bool(flags & 0x02)
            rst = bool(flags & 0x04)
            psh = bool(flags & 0x08)
            urg = bool(flags & 0x20)

            scan_type = None

            if syn and not fin and not rst:
                scan_type = "SYN"
            elif fin and not syn and not rst and not psh and not urg:
                scan_type = "FIN"
            elif flags == 0:
                scan_type = "NULL"
            elif fin and psh and urg and not syn:
                scan_type = "XMAS"

            if scan_type:
                is_scan, detail = self.portscan.process_packet(
                    ip.src, dst_port, now, scan_type
                )
                if is_scan:
                    if self.alert_callback:
                        self.alert_callback(ip.src, detail)

        elif proto == "UDP":
            is_scan, detail = self.portscan.process_packet(
                ip.src, dst_port, now, "UDP"
            )
            if is_scan:
                if self.alert_callback:
                    self.alert_callback(ip.src, detail)

    # ---------------- FIREWALL RELOAD ---------------- #

    def reload_firewall(self):
        from src.db.CRUD import readRules

        was_enabled = self.firewall.enabled
        if was_enabled:
            self.firewall.disable()

        self.firewall.load_rules(readRules())

        if was_enabled:
            self.firewall.enable()

    # ---------------- SNIFFER CONTROL ---------------- #

    def _get_iface(self):
        """
        Find the active non-loopback network interface.
        Falls back to scapy's default if nothing is found.
        Also sets self.local_ip to the interface's IPv4 address.
        """
        for name, addrs in scapy.conf.ifaces.items():
            if name == "lo" or name.startswith("lo"):
                continue
            if hasattr(addrs, "ip") and addrs.ip and addrs.ip != "0.0.0.0":
                self.local_ip = addrs.ip
                return name
        return None

    def start(self):
        iface = self._get_iface()
        self.sniffer = AsyncSniffer(
            iface=iface, prn=self._handle_packet, store=False
        )
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
