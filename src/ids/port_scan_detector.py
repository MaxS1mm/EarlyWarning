import time

class PortScanDetector:
    def __init__(self, window=10, port_threshold=20, rate_threshold=10):
        self.window = window
        self.port_threshold = port_threshold
        self.rate_threshold = rate_threshold
        self.scanner_data = {}
        self.last_alert = {}  # cooldown

    def process_packet(self, src_ip, dst_port, timestamp):
        if src_ip not in self.scanner_data:
            self.scanner_data[src_ip] = {
                "ports": set(),
                "timestamps": []
            }

        data = self.scanner_data[src_ip]
        data["ports"].add(dst_port)
        data["timestamps"].append(timestamp)

        # Keep only recent timestamps
        data["timestamps"] = [
            t for t in data["timestamps"]
            if timestamp - t <= self.window
        ]

        return self.check_scan(src_ip, timestamp)

    def check_scan(self, src_ip, now):
        data = self.scanner_data[src_ip]

        if (
            len(data["ports"]) > self.port_threshold and
            len(data["timestamps"]) > self.rate_threshold
        ):
            # cooldown (avoid spam)
            if src_ip in self.last_alert and now - self.last_alert[src_ip] < 10:
                return False, None

            self.last_alert[src_ip] = now
            return True, data

        return False, None