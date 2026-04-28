import time
from collections import Counter


SCAN_DESCRIPTIONS = {
    "SYN":  ("SYN (half-open) scan — sends SYN, never completes the handshake. "
             "Old logging tools miss it because no connection is 'established'."),
    "FIN":  ("FIN scan — sends FIN to every port. Closed ports "
             "must RST; open ports stay silent. Works only against some operating systems."),
    "NULL": ("NULL scan — no TCP flags at all. Same closed=RST / open=silent "
             "rule applies. Evasion: some firewalls pass null packets through."),
    "XMAS": ("XMAS scan — FIN+PSH+URG flags set (looks like a Christmas tree). "
             "Same detection trick as FIN/NULL."),
    "UDP":  ("UDP scan — probes UDP ports. ICMP 'unreachable' means closed; "
             "silence *might* mean open. Very slow; easily rate-limited."),
    "SLOW": ("Slow/low-and-slow scan — probes spread over minutes to stay "
             "below per-second rate thresholds. Caught by tracking a longer window."),
}


class PortScanDetector:
    def __init__(self,
                 fast_window=10,
                 fast_port_threshold=25,
                 fast_rate_threshold=10,
                 slow_window=180,
                 slow_port_threshold=40,
                 alert_cooldown=30):

        self.fast_window = fast_window
        self.fast_port_threshold = fast_port_threshold
        self.fast_rate_threshold = fast_rate_threshold
        self.slow_window = slow_window
        self.slow_port_threshold = slow_port_threshold
        self.alert_cooldown = alert_cooldown

        # { src_ip -> { "ports": set, "timestamps": [], "scan_types": set } }
        self.tracker = {}
        self.last_alert = {}  # { src_ip -> last alert timestamp }

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def process_packet(self, src_ip: str, dst_port: int,
                       timestamp: float, scan_type: str = "SYN"):
        
        data = self._get_or_create(src_ip)

        # Only record the first time we see each port
        if dst_port not in data["port_times"]:
            data["port_times"][dst_port] = timestamp

        data["timestamps"].append(timestamp)
        data["scan_types"].append((scan_type, timestamp))

        # Drop timestamps and ports outside the slow window
        data["timestamps"] = [
            t for t in data["timestamps"]
            if timestamp - t <= self.slow_window
        ]
        data["port_times"] = {
            port: t for port, t in data["port_times"].items()
            if timestamp - t <= self.slow_window
        }
        data["scan_types"] = [
            (st, t) for st, t in data["scan_types"]
            if timestamp - t <= self.slow_window
        ]

        return self._check(src_ip, timestamp)

    # helpers

    def _get_or_create(self, src_ip):
        if src_ip not in self.tracker:
            self.tracker[src_ip] = {
                "port_times": {},  # { port -> timestamp of when it was first seen }
                "timestamps": [],
                "scan_types": [],
            }
        return self.tracker[src_ip]

    def _check(self, src_ip, now):
        data = self.tracker[src_ip]
        active_ports = data["port_times"]

        # How many timestamps fall in the fast window?
        recent = [t for t in data["timestamps"] if now - t <= self.fast_window]

        # Only count ports seen within the fast window for fast scan
        fast_ports = {
            p for p, t in active_ports.items()
            if now - t <= self.fast_window
        }

        fast_scan = (
            len(fast_ports) >= self.fast_port_threshold and
            len(recent) >= self.fast_rate_threshold
        )
        slow_scan = (
            len(active_ports) >= self.slow_port_threshold
        )

        if not (fast_scan or slow_scan):
            return False, None

        # Cooldown — don't spam the same alert
        last = self.last_alert.get(src_ip, 0)
        if now - last < self.alert_cooldown:
            return False, None

        self.last_alert[src_ip] = now

        # Choose the scan type seen most often in the relevant window
        if slow_scan and not fast_scan:
            detected_type = "SLOW"
        else:
            type_counts = Counter(
                st for st, t in data["scan_types"]
                if now - t <= (self.fast_window if fast_scan else self.slow_window)
            )
            detected_type = type_counts.most_common(1)[0][0] if type_counts else "SYN"

        all_types = {st for st, _ in data["scan_types"]}
        detail = {
            "ports":       set(active_ports.keys()),
            "scan_type":   detected_type,
            "description": SCAN_DESCRIPTIONS.get(detected_type, "Unknown scan type"),
            "total_ports": len(active_ports),
            "scan_types":  all_types,
        }
        return True, detail
