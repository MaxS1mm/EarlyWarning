"""
terminal_controller.py

Handles all commands typed into the in-app terminal.
"""

import re
import threading
from src.db.CRUD import readRules
from .port_scanner import run_scan, QUICK_PORTS, METASPLOITABLE_VULNS


class TerminalController:
    def __init__(self, monitor, print_func):
        """
        monitor    – FlowMonitor instance (gives us the firewall + detector)
        print_func – function that writes a line to the terminal UI
        """
        self.monitor = monitor
        self.print = print_func

        self.commands = {
            "help":     self.cmd_help,
            "clear":    self.cmd_clear,
            "connections": self.cmd_connections,
            "scan":     self.cmd_scan,
            "rules":    self.cmd_rules,
            "firewall": self.cmd_firewall,
            "detector": self.cmd_detector,
        }

    # ===================== PARSER =====================

    def parse(self, raw_input):
        parts = raw_input.strip().split()
        if not parts:
            return None, []
        return parts[0].lower(), parts[1:]

    # ===================== ENTRY POINT =====================

    def handle(self, raw_input):
        cmd, args = self.parse(raw_input)
        if not cmd:
            return
        if cmd in self.commands:
            try:
                self.commands[cmd](args)
            except Exception as e:
                self.print(f"Error: {e}")
        else:
            self.print("Unknown command. Type 'help' for a list.")

    # ===================== COMMANDS =====================

    def cmd_help(self, args):
        self.print("=" * 50)
        self.print("Available commands")
        self.print("=" * 50)
        self.print("")
        self.print("  connections")
        self.print("      Show active network connections.")
        self.print("")
        self.print("  scan <ip>")
        self.print("      Quick scan: checks all known Metasploitable 2 ports.")
        self.print("  scan <ip> full")
        self.print("      Scan all ports 1-1024.")
        self.print("  scan <ip> ports <start>-<end>")
        self.print("      Scan a custom port range, e.g.: scan 192.168.1.5 ports 20-100")
        self.print("")
        self.print("  firewall status")
        self.print("      Show whether the firewall is on and its statistics.")
        self.print("  firewall on")
        self.print("      Enable the firewall (applies rules from the Rules page).")
        self.print("  firewall off")
        self.print("      Disable the firewall.")
        self.print("  firewall reload")
        self.print("      Reload rules from the database (use after adding new rules).")
        self.print("")
        self.print("  detector status")
        self.print("      Show port-scan detector settings and what scan types it catches.")
        self.print("")
        self.print("  rules")
        self.print("      Print all firewall rules from the database.")
        self.print("")
        self.print("  clear")
        self.print("      Clear this terminal output.")
        self.print("=" * 50)

    def cmd_clear(self, args):
        self.print("__CLEAR__")

    def cmd_connections(self, args):
        connections = self.monitor.get_active_connections()
        if not connections:
            self.print("No active connections.")
            return
        self.print(f"{'Proto':<6} {'Source':<22} {'Destination':<22} {'State':<6} {'Pkts'}")
        self.print("-" * 70)
        for (proto, src, sport, dst, dport), data in connections:
            self.print(
                f"{proto:<6} {src+':'+str(sport):<22} {dst+':'+str(dport):<22} "
                f"{data['state']:<6} {data['packets']}"
            )

    # ------------------------------------------------------------------ #
    # SCAN
    # ------------------------------------------------------------------ #

    def cmd_scan(self, args):
        """
        Usage:
          scan <ip>
          scan <ip> full
          scan <ip> ports <start>-<end>
        """
        if not args:
            self.print("Usage: scan <ip>  |  scan <ip> full  |  scan <ip> ports 20-100")
            return

        ip = args[0]
        if not self._valid_ip(ip):
            self.print(f"'{ip}' is not a valid IPv4 address.")
            return

        # --- decide which ports to scan ---
        if len(args) == 1:
            # Quick scan: just the Metasploitable 2 known ports
            ports = QUICK_PORTS
            self.print(f"Quick scan on {ip} ({len(ports)} known-vulnerable ports)")

        elif len(args) == 2 and args[1].lower() == "full":
            ports = list(range(1, 1025))
            self.print(f"Full scan on {ip} (ports 1-1024)")

        elif len(args) == 3 and args[1].lower() == "ports":
            ports = self._parse_port_range(args[2])
            if ports is None:
                self.print("Bad port range. Example: scan 10.0.0.1 ports 20-100")
                return
            self.print(f"Custom scan on {ip} (ports {args[2]})")

        else:
            self.print("Usage: scan <ip>  |  scan <ip> full  |  scan <ip> ports 20-100")
            return

        # Run the scan in a background thread so the UI stays responsive
        def _run():
            run_scan(ip, ports, self.print)

        threading.Thread(target=_run, daemon=True).start()

    # ------------------------------------------------------------------ #
    # FIREWALL
    # ------------------------------------------------------------------ #

    def cmd_firewall(self, args):
        """
        Usage:
          firewall status
          firewall on
          firewall off
          firewall reload
        """
        fw = self.monitor.firewall

        if not args:
            self.print("Usage: firewall <status|on|off|reload>")
            return

        sub = args[0].lower()

        if sub == "status":
            stats = fw.get_stats()
            state = "ON" if stats["enabled"] else "OFF"
            self.print(f"Firewall: {state}")
            self.print(f"  Rules loaded : {stats['rule_count']}")
            self.print(f"  Packets allowed : {stats['allowed']}")
            self.print(f"  Packets blocked : {stats['blocked']}")
            self.print(f"  Packets alerted : {stats['alerted']}")
            self.print("")
            self.print("How it works:")
            self.print("  Each packet is checked top-to-bottom against your rules.")
            self.print("  'deny'  -> packet is logged and dropped.")
            self.print("  'alert' -> packet is allowed but logged as suspicious.")
            self.print("  'allow' -> packet passes through silently.")
            self.print("  No match -> allow by default (permissive policy).")

        elif sub == "on":
            fw.load_rules(readRules())   # always reload fresh rules when enabling
            fw.enable()
            self.print(f"Firewall ON — {len(fw.rules)} rule(s) loaded.")

        elif sub == "off":
            fw.disable()
            self.print("Firewall OFF — all traffic passes through.")

        elif sub == "reload":
            # If the firewall is currently on, turn it off first so the
            # old nftables rules are removed before we load new ones.
            was_enabled = fw.enabled
            if was_enabled:
                fw.disable()

            fw.load_rules(readRules())

            if was_enabled:
                fw.enable()

            self.print(f"Rules reloaded — {len(fw.rules)} rule(s) now active.")

        else:
            self.print(f"Unknown sub-command '{sub}'. Use: status, on, off, reload")

    # ------------------------------------------------------------------ #
    # DETECTOR
    # ------------------------------------------------------------------ #

    def cmd_detector(self, args):
        """Show the port-scan detector settings and explain what it catches."""
        det = self.monitor.portscan

        self.print("=" * 55)
        self.print("  Port-Scan Detector")
        self.print("=" * 55)
        self.print(f"  Fast window     : {det.fast_window}s")
        self.print(f"  Fast thresholds : {det.fast_port_threshold} ports / "
                   f"{det.fast_rate_threshold} packets")
        self.print(f"  Slow window     : {det.slow_window}s")
        self.print(f"  Slow threshold  : {det.slow_port_threshold} distinct ports")
        self.print(f"  Alert cooldown  : {det.alert_cooldown}s between alerts per IP")
        self.print("")
        self.print("  Scan types detected:")
        from .port_scan_detector import SCAN_DESCRIPTIONS
        for name, desc in SCAN_DESCRIPTIONS.items():
            self.print(f"  [{name}]")
            self.print(f"    {desc}")
            self.print("")
        self.print("=" * 55)

    # ------------------------------------------------------------------ #
    # RULES
    # ------------------------------------------------------------------ #

    def cmd_rules(self, args):
        rules = readRules()
        if not rules:
            self.print("No rules in database. Add some on the Rules page.")
            return
        header = f"{'Protocol':<10} {'Src IP':<16} {'Dst IP':<16} {'SPort':<7} {'DPort':<7} Action"
        self.print(header)
        self.print("-" * len(header))
        for r in rules:
            self.print(
                f"{str(r['protocol']):<10} {str(r['src_ip']):<16} "
                f"{str(r['dst_ip']):<16} {str(r['src_port']):<7} "
                f"{str(r['dst_port']):<7} {str(r['action'])}"
            )

    # ===================== HELPERS =====================

    def _valid_ip(self, ip):
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip))

    def _parse_port_range(self, range_str):
        """Parse '20-100' into list(range(20, 101)). Returns None on error."""
        match = re.match(r"^(\d+)-(\d+)$", range_str)
        if not match:
            return None
        start, end = int(match.group(1)), int(match.group(2))
        if start < 1 or end > 65535 or start > end:
            return None
        return list(range(start, end + 1))
