import re
from src.db.CRUD import readRules

class TerminalController:
    def __init__(self, monitor, print_func):
        """
        monitor: your FlowMonitor instance
        print_func: function to output text to UI
        """
        self.monitor = monitor
        self.print = print_func

        self.commands = {
            "help": self.cmd_help,
            "clear": self.cmd_clear,
            "connections": self.cmd_connections,
            "scan": self.cmd_scan,
            "rules": self.cmd_rules,
        }

    # ================= PARSER =================
    def parse(self, raw_input):
        parts = raw_input.strip().split()
        if not parts:
            return None, []
        return parts[0].lower(), parts[1:]

    # ================= ENTRY POINT =================
    def handle(self, raw_input):
        cmd, args = self.parse(raw_input)

        if not cmd:
            return

        if cmd in self.commands:
            try:
                self.commands[cmd](args)
            except Exception as e:
                self.print(f"Error: {str(e)}")
        else:
            self.print("Unknown command. Type 'help'")

    # ================= COMMANDS =================
    def cmd_help(self, args):
        self.print("Available commands:")
        for cmd in self.commands:
            self.print(f" - {cmd}")

    def cmd_clear(self, args):
        # special signal to UI
        self.print("__CLEAR__")

    def cmd_connections(self, args):
        connections = self.monitor.get_active_connections()

        for (proto, src, sport, dst, dport), data in connections:
            self.print(
                f"{proto} {src}:{sport} -> {dst}:{dport} "
                f"{data['state']} Packets:{data['packets']}"
            )

    def cmd_scan(self, args):
        #port scan, vulnerability scan, etc.
        if len(args) != 1:
            self.print("Usage: scan <ip>")
            return

        ip = args[0]

        #nmap ...
        self.print(f"Scanning {ip}...")

    def cmd_rules(self, args):
        rules = readRules()
        header = "Protocol | Src Port | Dst Port | Src IP | Dst IP | Action"

        self.print(header)
        for r in rules:
            self.print(str(r["protocol"]) + " | " + str(r["src_port"]) + " | " + str(r["dst_port"]) + " | " + str(r["src_ip"]) + " | " + str(r["dst_ip"]) + " | " + str(r["action"]))

    # ================= HELPERS =================
    def valid_ip(self, ip):
        return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip)