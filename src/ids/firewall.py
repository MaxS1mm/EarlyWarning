"""
firewall.py

A software firewall that checks live packets against rules from the database.

On Linux (Ubuntu 24.04+), rules are also pushed into nftables so the
kernel itself blocks or logs traffic.  On macOS or other systems the
firewall still works, but only inside Python — it cannot truly block
packets at the OS level.

--- What is nftables? ---

nftables is the modern Linux firewall (it replaced iptables).  It
organises rules into *tables* and *chains*:

    table  –  a container that holds one or more chains.
    chain  –  an ordered list of rules.  A chain with a "hook" (like
              "input") tells the kernel to run every incoming packet
              through that list.

We create our own table called "ids_firewall" with one chain called
"input".  When the user turns the firewall off we simply delete the
whole table — that removes every rule in one command.

--- How alert rules work ---

"deny"  rules  -> nftables DROPs the packet (kernel discards it).
"alert" rules  -> nftables LOGs the packet AND ACCEPTs it.
                  Because the packet is accepted, it still reaches our
                  Python sniffer, which fires the UI alert callback.
"allow" rules  -> nftables ACCEPTs the packet (passes through).
"""

import platform
import subprocess


class Firewall:
    def __init__(self):
        self.enabled = False
        self.rules = []          # list of plain dicts from the database
        self.blocked_count = 0
        self.allowed_count = 0
        self.alert_count = 0

        # We only use nftables on Linux.
        # On macOS there is no nftables, so we skip those calls.
        self.is_linux = platform.system() == "Linux"

        # The nftables table and chain names we will create.
        # Using the "inet" family so the rules apply to both IPv4 and IPv6.
        self.TABLE_NAME = "ids_firewall"
        self.CHAIN_NAME = "input"

    # ------------------------------------------------------------------ #
    # Rule management
    # ------------------------------------------------------------------ #

    def load_rules(self, db_rules):
        """
        Accept the list of rules that readRules() returns.
        Each rule is a dict with keys:
            protocol, src_ip, dst_ip, src_port, dst_port, action
        """
        if not db_rules:
            self.rules = []
            return
        self.rules = [dict(r) for r in db_rules]

    # ------------------------------------------------------------------ #
    # Enable / disable
    # ------------------------------------------------------------------ #

    def enable(self):
        self.enabled = True

        if self.is_linux:
            self._add_nft_table()
            self._add_nft_rules()

    def disable(self):
        self.enabled = False

        if self.is_linux:
            self._remove_nft_table()

    # ------------------------------------------------------------------ #
    # Python-level packet checking  (works on every OS)
    #
    # flow_monitor.py calls check_packet() for every packet the sniffer
    # sees.  On Linux, "deny" packets never reach the sniffer because
    # nftables already dropped them.  "alert" and "allow" packets DO
    # reach the sniffer, so check_packet() can still fire the UI alert
    # callback and update the counters for those.
    # ------------------------------------------------------------------ #

    def _field_matches(self, rule_val, packet_val):
        """
        Compare one field from a rule against the actual packet value.
        Wildcards (None, '', '*', 'any', 0, '0') mean "match anything".
        """
        if rule_val in (None, "", "*", "any", 0, "0"):
            return True
        return str(rule_val).lower() == str(packet_val).lower()

    def check_packet(self, proto, src_ip, dst_ip, src_port, dst_port):
        """
        Walk the rule list top-to-bottom.  Return the first matching action.

        Returns:
            action (str)  – "allow", "deny", or "alert"
            rule   (dict) – the matching rule, or None
        """
        if not self.enabled:
            return "allow", None

        for rule in self.rules:
            if (self._field_matches(rule.get("protocol"), proto) and
                    self._field_matches(rule.get("src_ip"),   src_ip) and
                    self._field_matches(rule.get("dst_ip"),   dst_ip) and
                    self._field_matches(rule.get("src_port"), src_port) and
                    self._field_matches(rule.get("dst_port"), dst_port)):

                action = rule.get("action", "allow")

                if action == "deny":
                    self.blocked_count += 1
                elif action == "alert":
                    self.alert_count += 1
                else:
                    self.allowed_count += 1

                return action, rule

        # No rule matched — default: allow
        self.allowed_count += 1
        return "allow", None

    # ------------------------------------------------------------------ #
    # Stats
    # ------------------------------------------------------------------ #

    def get_stats(self):
        return {
            "enabled":    self.enabled,
            "rule_count": len(self.rules),
            "blocked":    self.blocked_count,
            "allowed":    self.allowed_count,
            "alerted":    self.alert_count,
        }

    # ================================================================== #
    #                       nftables helpers                              #
    # ================================================================== #

    def _run_nft(self, command):
        """
        Run a single nft command.

        'command' is the part after "nft", for example:
            "add table inet ids_firewall"

        Returns True if the command succeeded, False if it failed.
        """
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

    # ------------------------------------------------------------------ #
    # Table creation / deletion
    # ------------------------------------------------------------------ #

    def _add_nft_table(self):
        """
        Create our nftables table and a chain hooked into "input".

        The chain has:
          - type filter : we are filtering (blocking / allowing) packets
          - hook input  : check packets coming IN to this machine
          - priority 0  : run at the default priority
          - policy accept : if no rule matches, let the packet through

        If the table already exists, nft will just skip the creation.
        """
        # Step 1 — create the table
        self._run_nft(f"add table inet {self.TABLE_NAME}")

        # Step 2 — create the chain inside that table
        # We need to pass this as a raw string because of the braces and semicolons
        chain_cmd = (
            f"add chain inet {self.TABLE_NAME} {self.CHAIN_NAME} "
            f"{{ type filter hook input priority 0 ; policy accept ; }}"
        )
        subprocess.run(
            ["nft", chain_cmd],
            check=False,
            capture_output=True,
            shell=False,
        )
        # Fallback: try with shell=True in case the above didn't work
        # (nft sometimes needs the shell to parse the braces correctly)
        subprocess.run(
            f"nft '{chain_cmd}'",
            check=False,
            capture_output=True,
            shell=True,
        )

    def _remove_nft_table(self):
        """
        Delete our entire nftables table.

        This is the beauty of nftables vs iptables — deleting the table
        automatically removes every chain and rule inside it in one go.
        """
        self._run_nft(f"delete table inet {self.TABLE_NAME}")

    # ------------------------------------------------------------------ #
    # Building an nft rule string from a database rule
    # ------------------------------------------------------------------ #

    def _is_wildcard(self, value):
        """Return True if the value means 'match anything'."""
        return value in (None, "", "*", "any", 0, "0")

    def _build_nft_rule(self, rule, action_part):
        """
        Turn one database rule into an nft rule string.

        Parameters
        ----------
        rule         : dict – one row from the rules table
        action_part  : str  – what to append at the end, e.g. "drop" or
                              "log prefix \"IDS_ALERT: \" accept"

        Returns
        -------
        str – a complete "nft add rule ..." command

        Example
        -------
        Input:  rule = {protocol: "tcp", src_ip: "10.0.0.5", dst_port: 80}
                action_part = "drop"
        Output: "add rule inet ids_firewall input ip protocol tcp
                 ip saddr 10.0.0.5 tcp dport 80 drop"
        """
        # Start with the base command
        parts = [f"add rule inet {self.TABLE_NAME} {self.CHAIN_NAME}"]

        protocol = rule.get("protocol", "any")
        src_ip   = rule.get("src_ip", "")
        dst_ip   = rule.get("dst_ip", "")
        src_port = rule.get("src_port", 0)
        dst_port = rule.get("dst_port", 0)

        # --- Protocol filter ---
        # nft syntax: "ip protocol tcp"
        if not self._is_wildcard(protocol):
            parts.append(f"ip protocol {protocol}")

        # --- Source IP ---
        # nft syntax: "ip saddr 10.0.0.5"
        if not self._is_wildcard(src_ip):
            parts.append(f"ip saddr {src_ip}")

        # --- Destination IP ---
        # nft syntax: "ip daddr 192.168.1.1"
        if not self._is_wildcard(dst_ip):
            parts.append(f"ip daddr {dst_ip}")

        # --- Source port  (only makes sense for tcp / udp) ---
        # nft syntax: "tcp sport 8080"
        if not self._is_wildcard(src_port) and protocol in ("tcp", "udp"):
            parts.append(f"{protocol} sport {src_port}")

        # --- Destination port ---
        # nft syntax: "tcp dport 80"
        if not self._is_wildcard(dst_port) and protocol in ("tcp", "udp"):
            parts.append(f"{protocol} dport {dst_port}")

        # --- Action (drop / accept / log) ---
        parts.append(action_part)

        return " ".join(parts)

    # ------------------------------------------------------------------ #
    # Pushing the full rule set into nftables
    # ------------------------------------------------------------------ #

    def _add_nft_rules(self):
        """
        Loop through every loaded rule and add it to our nftables chain.

        Action mapping
        --------------
        deny  ->  "drop"
            The kernel silently discards the packet.  It never reaches
            our Python sniffer.

        alert ->  "log prefix \"IDS_ALERT: \" accept"
            The kernel writes a log line (visible in dmesg / journalctl)
            AND lets the packet through.  Because the packet is accepted,
            it still reaches our sniffer, where check_packet() fires the
            alert callback so the user sees it in the UI.

        allow ->  "accept"
            The kernel lets the packet through normally.
        """
        for rule in self.rules:
            action = rule.get("action", "allow")

            if action == "deny":
                nft_command = self._build_nft_rule(rule, "drop")
                self._run_nft(nft_command)

            elif action == "alert":
                # "log" writes to the kernel log, "accept" lets the packet
                # continue so our Python sniffer can also see it and fire
                # the in-app alert.
                nft_command = self._build_nft_rule(
                    rule,
                    'log prefix "IDS_ALERT: " accept'
                )
                self._run_nft(nft_command)

            else:
                # "allow" -> accept
                nft_command = self._build_nft_rule(rule, "accept")
                self._run_nft(nft_command)
