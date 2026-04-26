"""
terminal_controller.py

Handles all commands typed into the in-app terminal.
"""

import re
import threading
from src.db.CRUD import readRules, readRuleById, createRule, updateRule, deleteRule
from .port_scanner import run_scan, QUICK_PORTS, METASPLOITABLE_VULNS

# These are the only values the database accepts
VALID_PROTOCOLS = ("tcp", "udp", "icmp", "any")
VALID_ACTIONS   = ("allow", "deny", "alert")


class TerminalController:
    def __init__(self, monitor, print_func, refresh_rules_func=None,
                 start_live_connections_func=None):
        """
        monitor                    – FlowMonitor instance (firewall + detector)
        print_func                 – writes a line to the terminal UI
        refresh_rules_func         – called after rule changes so the Rules page
                                     updates automatically (can be None)
        start_live_connections_func – called to start live-updating connections
                                     view in the terminal (can be None)
        """
        self.monitor = monitor
        self.print = print_func
        self.refresh_rules = refresh_rules_func
        self.start_live_connections = start_live_connections_func

        self.commands = {
            "help":       self.cmd_help,
            "clear":      self.cmd_clear,
            "connections": self.cmd_connections,
            "scan":       self.cmd_scan,
            "rules":      self.cmd_rules,
            "addrule":    self.cmd_addrule,
            "editrule":   self.cmd_editrule,
            "deleterule": self.cmd_deleterule,
            "firewall":   self.cmd_firewall,
            "detector":   self.cmd_detector,
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
        self.print("=" * 60)
        self.print("Available commands")
        self.print("=" * 60)
        self.print("")
        self.print("  connections")
        self.print("      Live view of active connections (updates every 2s).")
        self.print("      Press Ctrl+C to stop.")
        self.print("")
        self.print("  scan <ip>")
        self.print("      Quick scan: checks all known Metasploitable 2 ports.")
        self.print("  scan <ip> full")
        self.print("      Scan all ports 1-1024.")
        self.print("  scan <ip> ports <start>-<end>")
        self.print("      Scan a custom port range.")
        self.print("")
        self.print("  rules")
        self.print("      Print all firewall rules from the database.")
        self.print("")
        self.print("  addrule <protocol> <src_ip> <dst_ip> <src_port> <dst_port> <action>")
        self.print("      Add a new rule.  Use 'any' or '0' for wildcards.")
        self.print("      Example: addrule tcp any 192.168.1.10 0 80 deny")
        self.print("")
        self.print("  editrule <id> <protocol> <src_ip> <dst_ip> <src_port> <dst_port> <action>")
        self.print("      Update an existing rule by its ID.")
        self.print("      Example: editrule 3 tcp any 192.168.1.10 0 443 alert")
        self.print("")
        self.print("  deleterule <id>")
        self.print("      Delete a rule by its ID.")
        self.print("")
        self.print("  firewall status")
        self.print("      Show whether the firewall is on and its statistics.")
        self.print("  firewall on")
        self.print("      Enable the firewall.")
        self.print("  firewall off")
        self.print("      Disable the firewall.")
        self.print("      Rules are reloaded automatically when added, edited, or deleted.")
        self.print("")
        self.print("  detector status")
        self.print("      Show port-scan detector settings.")
        self.print("")
        self.print("  clear")
        self.print("      Clear this terminal output.")
        self.print("=" * 60)

    def cmd_clear(self, args):
        self.print("__CLEAR__")

    def cmd_connections(self, args):
        if self.start_live_connections:
            self.start_live_connections()
        else:
            self._print_connections_once()

    def _print_connections_once(self):
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
        if not args:
            self.print("Usage: scan <ip>  |  scan <ip> full  |  scan <ip> ports 20-100")
            return

        ip = args[0]
        if not self._valid_ip(ip):
            self.print(f"'{ip}' is not a valid IPv4 address.")
            return

        if len(args) == 1:
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

        def _run():
            run_scan(ip, ports, self.print)

        threading.Thread(target=_run, daemon=True).start()

    # ------------------------------------------------------------------ #
    # RULES — list, add, edit, delete
    # ------------------------------------------------------------------ #

    def cmd_rules(self, args):
        """Print all firewall rules from the database."""
        rules = readRules()
        if not rules:
            self.print("No rules in database.")
            return

        # Table header
        header = (f"{'ID':<5} {'Protocol':<10} {'Src IP':<16} {'Dst IP':<16} "
                  f"{'SPort':<7} {'DPort':<7} Action")
        self.print(header)
        self.print("-" * len(header))

        for r in rules:
            self.print(
                f"{str(r['rid']):<5} "
                f"{str(r['protocol']):<10} "
                f"{str(r['src_ip'] or 'any'):<16} "
                f"{str(r['dst_ip'] or 'any'):<16} "
                f"{str(r['src_port'] or 'any'):<7} "
                f"{str(r['dst_port'] or 'any'):<7} "
                f"{str(r['action'])}"
            )

    def cmd_addrule(self, args):
        """
        Add a new firewall rule.
        Usage: addrule <protocol> <src_ip> <dst_ip> <src_port> <dst_port> <action>

        Use 'any' for wildcard IPs and '0' for wildcard ports.
        Example: addrule tcp any 192.168.1.10 0 80 deny
        """
        if len(args) != 6:
            self.print("Usage: addrule <protocol> <src_ip> <dst_ip> <src_port> <dst_port> <action>")
            self.print("Example: addrule tcp any 192.168.1.10 0 80 deny")
            return

        protocol = args[0].lower()
        src_ip   = args[1]
        dst_ip   = args[2]
        action   = args[5].lower()

        # Validate protocol
        if protocol not in VALID_PROTOCOLS:
            self.print(f"Invalid protocol '{protocol}'. Must be one of: {', '.join(VALID_PROTOCOLS)}")
            return

        # Validate action
        if action not in VALID_ACTIONS:
            self.print(f"Invalid action '{action}'. Must be one of: {', '.join(VALID_ACTIONS)}")
            return

        # Parse ports — must be numbers
        try:
            src_port = int(args[3])
            dst_port = int(args[4])
        except ValueError:
            self.print("Ports must be numbers. Use 0 for 'any'.")
            return

        if src_port < 0 or src_port > 65535 or dst_port < 0 or dst_port > 65535:
            self.print("Ports must be between 0 and 65535.")
            return

        # Normalise wildcard IPs — store as empty string in the database
        if src_ip.lower() in ("any", "*", "0"):
            src_ip = ""
        if dst_ip.lower() in ("any", "*", "0"):
            dst_ip = ""

        # Save to database
        createRule(protocol, src_ip, dst_ip, src_port, dst_port, action)
        self.print(f"Rule added: {protocol} {src_ip or 'any'}:{src_port} -> {dst_ip or 'any'}:{dst_port} [{action}]")

        # Refresh the Rules page in the UI if we have a callback
        if self.refresh_rules:
            self.refresh_rules()

    def cmd_editrule(self, args):
        """
        Update an existing rule by its ID.
        Usage: editrule <id> <protocol> <src_ip> <dst_ip> <src_port> <dst_port> <action>

        Example: editrule 3 tcp any 192.168.1.10 0 443 alert
        """
        if len(args) != 7:
            self.print("Usage: editrule <id> <protocol> <src_ip> <dst_ip> <src_port> <dst_port> <action>")
            self.print("Example: editrule 3 tcp any 192.168.1.10 0 443 alert")
            return

        # Parse the rule ID
        try:
            rid = int(args[0])
        except ValueError:
            self.print("Rule ID must be a number.")
            return

        # Check the rule actually exists
        existing = readRuleById(rid)
        if existing is None:
            self.print(f"No rule found with ID {rid}. Use 'rules' to see all rule IDs.")
            return

        protocol = args[1].lower()
        src_ip   = args[2]
        dst_ip   = args[3]
        action   = args[6].lower()

        # Validate protocol
        if protocol not in VALID_PROTOCOLS:
            self.print(f"Invalid protocol '{protocol}'. Must be one of: {', '.join(VALID_PROTOCOLS)}")
            return

        # Validate action
        if action not in VALID_ACTIONS:
            self.print(f"Invalid action '{action}'. Must be one of: {', '.join(VALID_ACTIONS)}")
            return

        # Parse ports
        try:
            src_port = int(args[4])
            dst_port = int(args[5])
        except ValueError:
            self.print("Ports must be numbers. Use 0 for 'any'.")
            return

        if src_port < 0 or src_port > 65535 or dst_port < 0 or dst_port > 65535:
            self.print("Ports must be between 0 and 65535.")
            return

        # Normalise wildcard IPs
        if src_ip.lower() in ("any", "*", "0"):
            src_ip = ""
        if dst_ip.lower() in ("any", "*", "0"):
            dst_ip = ""

        # Update in database
        updateRule(rid, protocol, src_ip, dst_ip, src_port, dst_port, action)
        self.print(f"Rule #{rid} updated: {protocol} {src_ip or 'any'}:{src_port} -> {dst_ip or 'any'}:{dst_port} [{action}]")

        if self.refresh_rules:
            self.refresh_rules()

    def cmd_deleterule(self, args):
        """
        Delete a rule by its ID.
        Usage: deleterule <id>
        """
        if len(args) != 1:
            self.print("Usage: deleterule <id>")
            return

        try:
            rid = int(args[0])
        except ValueError:
            self.print("Rule ID must be a number.")
            return

        # Check the rule exists before deleting
        existing = readRuleById(rid)
        if existing is None:
            self.print(f"No rule found with ID {rid}. Use 'rules' to see all rule IDs.")
            return

        deleteRule(rid)
        self.print(f"Rule #{rid} deleted.")

        if self.refresh_rules:
            self.refresh_rules()

    # ------------------------------------------------------------------ #
    # FIREWALL
    # ------------------------------------------------------------------ #

    def cmd_firewall(self, args):
        fw = self.monitor.firewall

        if not args:
            self.print("Usage: firewall <status|on|off>")
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
            if fw.enabled:
                self.print("The firewall is already activated.")
                return
            fw.load_rules(readRules())
            fw.enable()
            self.print(f"Firewall ON — {len(fw.rules)} rule(s) loaded.")

        elif sub == "off":
            if not fw.enabled:
                self.print("The firewall is already deactivated.")
                return
            fw.disable()
            self.print("Firewall OFF — all traffic passes through.")

        else:
            self.print(f"Unknown sub-command '{sub}'. Use: status, on, off")

    # ------------------------------------------------------------------ #
    # DETECTOR
    # ------------------------------------------------------------------ #

    def cmd_detector(self, args):
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
