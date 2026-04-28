import platform
import subprocess


class Firewall:
    def __init__(self):
        self.enabled = False
        self.rules = []
        self.allowed_count = 0
        self.alert_count = 0

        self.is_linux = platform.system() == "Linux"

        self.TABLE_NAME = "ids_firewall"
        self.INPUT_CHAIN = "input"
        self.OUTPUT_CHAIN = "output"

    # load db rules

    def load_rules(self, db_rules):
        if not db_rules:
            self.rules = []
            return
        self.rules = [dict(r) for r in db_rules]

    # Enable / disable

    def enable(self):
        self.enabled = True

        if self.is_linux:
            self._add_nft_table()
            self._add_nft_rules()

    def disable(self):
        self.enabled = False

        if self.is_linux:
            self._remove_nft_table()

    # Alert detection

    def _field_matches(self, rule_val, packet_val):
        if rule_val in (None, "", "*", "any", 0, "0"):
            return True
        return str(rule_val).lower() == str(packet_val).lower()

    def check_alert(self, proto, src_ip, dst_ip, src_port, dst_port):
        # Returns: matched (bool) – True if the packet matches an alert rule, rule (dict) – the matching rule, or None
        if not self.enabled:
            return False, None

        for rule in self.rules:
            if rule.get("action") != "alert":
                continue

            if (self._field_matches(rule.get("protocol"), proto) and
                    self._field_matches(rule.get("src_ip"),   src_ip) and
                    self._field_matches(rule.get("dst_ip"),   dst_ip) and
                    self._field_matches(rule.get("src_port"), src_port) and
                    self._field_matches(rule.get("dst_port"), dst_port)):
                self.alert_count += 1
                return True, rule

        self.allowed_count += 1
        return False, None

    # Stats

    def get_stats(self):
        return {
            "enabled":    self.enabled,
            "rule_count": len(self.rules),
            "allowed":    self.allowed_count,
            "alerted":    self.alert_count,
        }

    # nftables helpers

    def _run_nft(self, command):
        #run an nftables command
        full_command = ["nft"] + command.split()

        try:
            subprocess.run(
                full_command,
                check=True,           # raise an error if the command fails
                capture_output=True,   # don't print nft output to the terminal
                text=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    # Table creation / deletion

    def _add_nft_table(self):
        """
        Create our nftables table with two chains:
          - input  : filters packets coming IN to this machine
          - output : filters packets going OUT from this machine
        """
        self._run_nft(f"add table inet {self.TABLE_NAME}")

        # Create the input chain (incoming traffic)
        input_cmd = (
            f"add chain inet {self.TABLE_NAME} {self.INPUT_CHAIN} "
            f"{{ type filter hook input priority 0 ; policy accept ; }}"
        )
        subprocess.run(
            ["nft", input_cmd],
            check=False,
            capture_output=True,
            shell=False,
        )
        subprocess.run(
            f"nft '{input_cmd}'",
            check=False,
            capture_output=True,
            shell=True,
        )

        # Create the output chain (outgoing traffic)
        output_cmd = (
            f"add chain inet {self.TABLE_NAME} {self.OUTPUT_CHAIN} "
            f"{{ type filter hook output priority 0 ; policy accept ; }}"
        )
        subprocess.run(
            ["nft", output_cmd],
            check=False,
            capture_output=True,
            shell=False,
        )
        subprocess.run(
            f"nft '{output_cmd}'",
            check=False,
            capture_output=True,
            shell=True,
        )

    def _remove_nft_table(self):
        #flush table from nftables
        self._run_nft(f"delete table inet {self.TABLE_NAME}")

    # nft command from a database rule

    def _is_wildcard(self, value):
        return value in (None, "", "*", "any", 0, "0")

    def _build_nft_rule(self, rule, action_part, chain):
        """
        rule         : dict – one row from the rules table
        action_part  : str  – e.g. "drop" or "log prefix \"IDS_ALERT: \" accept"
        chain        : str  – which chain to add to ("input" or "output")
        """
        parts = [f"add rule inet {self.TABLE_NAME} {chain}"]

        protocol = rule.get("protocol", "any")
        src_ip   = rule.get("src_ip", "")
        dst_ip   = rule.get("dst_ip", "")
        src_port = rule.get("src_port", 0)
        dst_port = rule.get("dst_port", 0)

        # Protocol filter
        # nft syntax: "ip protocol tcp"
        if not self._is_wildcard(protocol):
            parts.append(f"ip protocol {protocol}")

        # Source IP 
        # nft syntax: "ip saddr 10.0.0.5"
        if not self._is_wildcard(src_ip):
            parts.append(f"ip saddr {src_ip}")

        # Destination IP
        # nft syntax: "ip daddr 192.168.1.1"
        if not self._is_wildcard(dst_ip):
            parts.append(f"ip daddr {dst_ip}")

        # Source port  (only makes sense for tcp / udp)
        # nft syntax: "tcp sport 8080"
        if not self._is_wildcard(src_port) and protocol in ("tcp", "udp"):
            parts.append(f"{protocol} sport {src_port}")

        # Destination port
        # nft syntax: "tcp dport 80"
        if not self._is_wildcard(dst_port) and protocol in ("tcp", "udp"):
            parts.append(f"{protocol} dport {dst_port}")

        # Action (drop / accept / log)
        parts.append(action_part)

        return " ".join(parts)

    # Pushing full rule set into nftables
    def _add_nft_rules(self):

        for rule in self.rules:
            action = rule.get("action", "allow")

            if action == "deny":
                action_part = "drop"
            elif action == "alert":
                action_part = 'log prefix "IDS_ALERT: " accept'
            else:
                action_part = "accept"

            # Add the rule to both input and output chains
            for chain in (self.INPUT_CHAIN, self.OUTPUT_CHAIN):
                nft_command = self._build_nft_rule(rule, action_part, chain)
                self._run_nft(nft_command)
