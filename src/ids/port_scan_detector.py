"""
port_scan_detector.py

Detects several common port-scanning techniques that attackers use to
stay hidden while mapping a target's open ports.

Scan types detected
-------------------
SYN   – Half-open scan. Sends SYN but never finishes the handshake.
        Many older logging systems only record completed connections, so
        this scan often goes unnoticed.

FIN   – Sends a FIN packet to every port. Closed ports reply with RST;
        open ports silently drop it. Works because the TCP spec says a
        port with no listener should RST an unexpected FIN.

NULL  – Same idea as FIN but with *no* TCP flags set at all.

XMAS  – Sets FIN + PSH + URG simultaneously (it "lights up like a
        Christmas tree"). Same open/closed behaviour as FIN/NULL.

UDP   – Sends UDP datagrams. An ICMP "port unreachable" reply means
        closed; no reply might mean open. Slower than TCP scans.

SLOW  – Spreads the probe across minutes instead of seconds so
        rate-based detectors don't fire. We catch it by tracking a
        longer time window with a lower rate requirement.
"""

import time


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
    """
    Parameters
    ----------
    fast_window          Seconds to look back for a fast scan burst.
    fast_port_threshold  Distinct ports needed in fast_window to raise alert.
    fast_rate_threshold  Packets needed in fast_window to raise alert.
    slow_window          Longer look-back window for slow scans.
    slow_port_threshold  Distinct ports over slow_window to raise a slow-scan alert.
    alert_cooldown       Minimum seconds between repeated alerts for the same IP.
    """

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
        """
        Record one suspicious packet and check whether it looks like a scan.

        scan_type should be one of: "SYN", "FIN", "NULL", "XMAS", "UDP".

        Returns (is_scan: bool, detail: dict | None).
        detail contains 'ports', 'scan_type', 'description', 'total_ports'.
        """
        data = self._get_or_create(src_ip)

        # Only record the first time we see each port
        if dst_port not in data["port_times"]:
            data["port_times"][dst_port] = timestamp

        data["timestamps"].append(timestamp)
        data["scan_types"].add(scan_type)

        # Drop timestamps and ports outside the slow window
        data["timestamps"] = [
            t for t in data["timestamps"]
            if timestamp - t <= self.slow_window
        ]
        data["port_times"] = {
            port: t for port, t in data["port_times"].items()
            if timestamp - t <= self.slow_window
        }

        return self._check(src_ip, timestamp)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _get_or_create(self, src_ip):
        if src_ip not in self.tracker:
            self.tracker[src_ip] = {
                "port_times": {},  # { port -> timestamp of when it was first seen }
                "timestamps": [],
                "scan_types": set(),
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

        # Choose the most descriptive scan type label
        if slow_scan and not fast_scan:
            detected_type = "SLOW"
        elif data["scan_types"]:
            non_syn = [t for t in data["scan_types"] if t != "SYN"]
            detected_type = non_syn[0] if non_syn else "SYN"
        else:
            detected_type = "SYN"

        detail = {
            "ports":       set(active_ports.keys()),
            "scan_type":   detected_type,
            "description": SCAN_DESCRIPTIONS.get(detected_type, "Unknown scan type"),
            "total_ports": len(active_ports),
            "scan_types":  data["scan_types"].copy(),
        }
        return True, detail
