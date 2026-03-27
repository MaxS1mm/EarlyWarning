import time
import threading
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
from .port_scan_detector import PortScanDetector
from .notifications import notification


class FlowMonitor:
    def __init__(self, alert_callback=None, log_file="ids_log.txt"):
        self.connections = {}
        self.lock = threading.Lock()
        self.sniffer = None
        self.TIMEOUT = 60

        self.portscan = PortScanDetector()
        self.alert_callback = alert_callback

        self.log_file = log_file

    # ---------------- LOGGING ---------------- #
    def notify_alert(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        notification(f"[{timestamp}]", f"{message}")


    def log_alert(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] {message}"

        with open(self.log_file, "a") as f:
            f.write(log_msg + "\n")

    # ---------------- CONNECTION TRACKING ---------------- #
    def _normalize_key(self, proto, src, sport, dst, dport):
        if (src, sport) < (dst, dport):
            return (proto, src, sport, dst, dport)
        else:
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

        key = self._normalize_key(proto, ip.src, l4.sport, ip.dst, l4.dport)

        # ---------------- CONNECTION TRACKING ---------------- #
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
        if proto == "TCP" and l4.flags == "S":  # SYN only
            is_scan, data = self.portscan.process_packet(
                ip.src, l4.dport, now
            )

            if is_scan:
                msg = f"⚠️ Port scan detected from {ip.src} | Ports: {len(data['ports'])}"

                self.notify_alert(msg)
                self.log_alert(msg)

                if self.alert_callback:
                    self.alert_callback(ip.src, data)

    # ---------------- SNIFFER CONTROL ---------------- #
    def start(self, iface=None):
        self.sniffer = AsyncSniffer(
            prn=self._handle_packet,
            store=False
        )
        self.sniffer.start()
        self.notify_alert("Sniffer started")

    def stop(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            self.notify_alert("Sniffer stopped")

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