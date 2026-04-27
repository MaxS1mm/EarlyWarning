import tkinter, socket, time
import customtkinter as ctk
from src.db.CRUD import createRule, readRules, updateRule, deleteRule, createLog, readLogs
from ..ids.flow_monitor import FlowMonitor
from src.ids.terminal_controller import TerminalController


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        my_ip = self.get_my_ip()

        self.title("Early Warning - An Intrusion Detection System")
        self.geometry("1000x750")

        self.monitor = FlowMonitor(
            alert_callback=lambda ip, data: self.after(0, self.log_alert, ip, data)
        )
        self.terminal = TerminalController(
            monitor=self.monitor,
            print_func=self.terminal_print,
            refresh_rules_func=lambda: refresh_rule_view(self),
            start_live_connections_func=self._start_live_connections
        )
        # Layout: top bar on row 0, main content fills row 1
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ===================== TOP BAR =====================
        self.topbar_frame = ctk.CTkFrame(self, height=50, corner_radius=0)
        self.topbar_frame.grid(row=0, column=0, sticky="ew")

        # Give every column equal weight so they share the space evenly
        for col in range(5):
            self.topbar_frame.columnconfigure(col, weight=1)

        ctk.CTkLabel(self.topbar_frame, text="EarlyWarning",
                     font=ctk.CTkFont(size=20, weight="bold")).grid(
                         row=0, column=0, padx=20, pady=10, sticky="ew")

        ctk.CTkButton(self.topbar_frame, text="Connections",
                      command=lambda: self.show_frame("connections")).grid(
                          row=0, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkButton(self.topbar_frame, text="Logs",
                      command=lambda: self.show_frame("logs")).grid(
                          row=0, column=2, padx=10, pady=10, sticky="ew")

        ctk.CTkButton(self.topbar_frame, text="Rules",
                      command=lambda: self.show_frame("rules")).grid(
                          row=0, column=3, padx=10, pady=10, sticky="ew")

        ctk.CTkButton(self.topbar_frame, text="Terminal",
                      command=lambda: self.show_frame("terminal")).grid(
                          row=0, column=4, padx=10, pady=10, sticky="ew")

        # ===================== MAIN FRAMES =====================
        self.frames = {}

        for name in ["connections", "logs", "rules", "terminal"]:
            frame = ctk.CTkFrame(self)
            frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
            frame.grid_remove()
            self.frames[name] = frame

        # ===================== CONNECTIONS FRAME =====================
        conn_frame = self.frames["connections"]
        conn_frame.grid_rowconfigure(1, weight=1)
        conn_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(conn_frame, text="Active Connections",
                     font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(10, 5))

        self.conn_textbox = ctk.CTkTextbox(
            conn_frame, wrap="none", fg_color="#0d0d0d",
            text_color="#e0e0e0", font=("Courier", 12)
        )
        self.conn_textbox.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Refresh the connections list every 2 seconds
        self._refresh_connections()

        # ===================== LOGS FRAME =====================
        logs_frame = self.frames["logs"]
        logs_frame.grid_rowconfigure(0, weight=1)
        logs_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(logs_frame, text="Security Logs",
                     font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(10, 5))

        self.log_textbox = ctk.CTkTextbox(
            logs_frame, wrap="word", fg_color="#0d0d0d",
            text_color="#e0e0e0", font=("Courier", 12)
        )
        self.log_textbox.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Button row for Clear and Export
        log_buttons = ctk.CTkFrame(logs_frame, fg_color="transparent")
        log_buttons.pack(pady=(0, 10))

        ctk.CTkButton(log_buttons, text="Clear Display",
                      command=self._clear_logs).grid(row=0, column=0, padx=10)

        ctk.CTkButton(log_buttons, text="View All Logs",
                      command=self._export_logs).grid(row=0, column=1, padx=10)

        # Load any existing logs from the database into the display
        self._load_saved_logs()

        # ===================== RULES FRAME =====================
        rules = self.frames["rules"]

        ctk.CTkButton(rules, text="Create New Rule",
                      command=self.open_new_rule_popup).pack(pady=10)

        self.rules_frame = ctk.CTkScrollableFrame(rules)
        self.rules_frame.pack(fill="both", expand=True)

        # ===================== TERMINAL FRAME =====================
        terminal = self.frames["terminal"]

        self.terminal_output = ctk.CTkTextbox(
            terminal, wrap="word", fg_color="black", text_color="white"
        )
        self.terminal_output.pack(fill="both", expand=True, padx=10, pady=10)

        self.terminal.print(f"Type 'help' for a list of commands")

        self.terminal_input = ctk.CTkEntry(terminal)
        self.terminal_input.pack(fill="x", padx=10, pady=(0, 10))
        self.terminal_input.bind("<Return>", self.handle_terminal_input)
        self.terminal_input.bind("<Up>", self.history_up)
        self.terminal_input.bind("<Down>", self.history_down)

        # Command history — stores every command the user has typed.
        # history_index points to where we are while scrolling with
        # the arrow keys.  -1 means "not scrolling, show blank input".
        self.command_history = []
        self.history_index = -1

        # Live connections mode — when active, the terminal auto-refreshes
        # the connections table every 2 seconds.  Ctrl+C stops it.
        # _live_conn_timer holds the after() ID so we can cancel it.
        self._live_conn_timer = None
        self.terminal_input.bind("<Control-c>", self._stop_live_connections)

        # Show logs by default
        self.show_frame("logs")

    # ===================== NAVIGATION =====================

    def show_frame(self, name):
        for frame in self.frames.values():
            frame.grid_remove()
        self.frames[name].grid()

    # ===================== LOGGING =====================

    def log_alert(self, src_ip, data):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        alert_type = data.get("type", "")

        if alert_type == "firewall_alert":
            rule = data.get("rule") or {}
            message = (f"FIREWALL ALERT  {src_ip}"
                       f"  ->  proto={rule.get('protocol','?')} "
                       f"dst={rule.get('dst_ip','?')}:{rule.get('dst_port','?')}")

        else:
            scan_type = data.get("scan_type", "SCAN")
            total = data.get("total_ports", len(data.get("ports", [])))
            desc = data.get("description", "")
            message = (f"PORT SCAN [{scan_type}]  from {src_ip}"
                       f"  |  {total} port(s) probed  —  {desc}")

        # Save to database
        createLog(timestamp, message)

        # Show in the UI
        line = f"[{timestamp}]  {message}\n"
        self.log_textbox.insert("end", line)
        self.log_textbox.see("end")

    def _clear_logs(self):
        self.log_textbox.delete("1.0", "end")

    def _load_saved_logs(self):
        logs = readLogs()
        for log in logs:
            line = f"[{log['timestamp']}]  {log['message']}\n"
            self.log_textbox.insert("end", line)
        if logs:
            self.log_textbox.see("end")

    def _export_logs(self):
        logs = readLogs()
        if not logs:
            self.log_textbox.insert("end", "[System] No logs in database.\n")
            self.log_textbox.see("end")
            return

        # Open a popup window showing all logs from the database
        popup = ctk.CTkToplevel(self)
        popup.geometry("800x500")
        popup.title("All Logs")

        textbox = ctk.CTkTextbox(
            popup, wrap="word", fg_color="#0d0d0d",
            text_color="#e0e0e0", font=("Courier", 12)
        )
        textbox.pack(fill="both", expand=True, padx=10, pady=10)

        for log in logs:
            textbox.insert("end", f"[{log['timestamp']}]  {log['message']}\n")

        textbox.configure(state="disabled")

    # ===================== CONNECTIONS =====================

    def _refresh_connections(self):
        connections = self.monitor.get_active_connections()

        # Remember where the user has scrolled to before we clear
        # the textbox.  yview() returns a tuple like (0.0, 0.35)
        # which represents the top and bottom of the visible area
        # as fractions of the total content.
        scroll_position = self.conn_textbox.yview()

        self.conn_textbox.configure(state="normal")
        self.conn_textbox.delete("1.0", "end")

        header = f"{'Proto':<8} {'Source':<24} {'Destination':<24} {'State':<8} {'Pkts':<8} {'Bytes'}\n"
        self.conn_textbox.insert("end", header)
        self.conn_textbox.insert("end", "-" * 80 + "\n")

        if not connections:
            self.conn_textbox.insert("end", "No active connections.\n")
        else:
            for (proto, src, sport, dst, dport), data in connections:
                line = (f"{proto:<8} {src + ':' + str(sport):<24} "
                        f"{dst + ':' + str(dport):<24} {data['state']:<8} "
                        f"{data['packets']:<8} {data['bytes']}\n")
                self.conn_textbox.insert("end", line)

        self.conn_textbox.configure(state="disabled")

        # Restore the scroll position so the view doesn't jump
        self.conn_textbox.yview_moveto(scroll_position[0])

        # Schedule the next refresh in 2 seconds
        self.after(2000, self._refresh_connections)

    # ===================== LIVE CONNECTIONS (TERMINAL) =====================

    def _start_live_connections(self):
        # If already running, do nothing
        if self._live_conn_timer is not None:
            return

        # Disable the input field so the user can't type other commands
        self.terminal_input.configure(state="disabled")

        self.terminal_print("Live connections view — press Ctrl+C to stop.")
        self.terminal_print("")
        self._live_conn_tick()

    def _live_conn_tick(self):
        connections = self.monitor.get_active_connections()

        # Build the table as a list of lines
        header = (f"{'Proto':<8} {'Source':<24} {'Destination':<24} "
                  f"{'State':<8} {'Pkts':<8} {'Bytes'}")
        separator = "-" * 80
        lines = [header, separator]

        if not connections:
            lines.append("No active connections.")
        else:
            for (proto, src, sport, dst, dport), data in connections:
                lines.append(
                    f"{proto:<8} {src + ':' + str(sport):<24} "
                    f"{dst + ':' + str(dport):<24} {data['state']:<8} "
                    f"{data['packets']:<8} {data['bytes']}"
                )

        lines.append("")
        lines.append("Press Ctrl+C to stop.")

        # Save the scroll position before clearing
        scroll_position = self.terminal_output.yview()

        # Clear the terminal and print the updated table
        self.terminal_output.configure(state="normal")
        self.terminal_output.delete("1.0", "end")
        for line in lines:
            self.terminal_output.insert("end", line + "\n")
        self.terminal_output.configure(state="disabled")

        # Restore the scroll position so the view doesn't jump
        self.terminal_output.yview_moveto(scroll_position[0])

        # Schedule the next tick in 2 seconds
        self._live_conn_timer = self.after(2000, self._live_conn_tick)

    def _stop_live_connections(self, event=None):
        # Only do something if live mode is actually running
        if self._live_conn_timer is None:
            return

        # Cancel the scheduled refresh
        self.after_cancel(self._live_conn_timer)
        self._live_conn_timer = None

        # Re-enable the input field
        self.terminal_input.configure(state="normal")
        self.terminal_input.focus_set()

        self.terminal_print("")
        self.terminal_print("Live view stopped.")

    # ===================== TERMINAL =====================

    def handle_terminal_input(self, event=None):
        raw = self.terminal_input.get()
        self.terminal_input.delete(0, "end")

        # Save the command to history (skip blank lines)
        if raw.strip():
            self.command_history.append(raw)

        # Reset the history position so the next Up press starts
        # from the most recent command again
        self.history_index = -1

        self.terminal_print(f"> {raw}")
        self.terminal.handle(raw)

    def history_up(self, event=None):
        """Pressing Up scrolls back through previous commands."""
        if not self.command_history:
            return

        # If we're not scrolling yet, start from the last command.
        # Otherwise move one step further back.
        if self.history_index == -1:
            self.history_index = len(self.command_history) - 1
        elif self.history_index > 0:
            self.history_index -= 1

        # Replace the current input with the historical command
        self.terminal_input.delete(0, "end")
        self.terminal_input.insert(0, self.command_history[self.history_index])

    def history_down(self, event=None):
        """Pressing Down scrolls forward through previous commands."""
        if not self.command_history:
            return

        if self.history_index == -1:
            # Already at the bottom, nothing to do
            return

        if self.history_index < len(self.command_history) - 1:
            # Move forward one step
            self.history_index += 1
            self.terminal_input.delete(0, "end")
            self.terminal_input.insert(0, self.command_history[self.history_index])
        else:
            # We've gone past the newest command — clear the input
            self.history_index = -1
            self.terminal_input.delete(0, "end")

    def terminal_print(self, text):
        self.terminal_output.configure(state="normal")
        if text == "__CLEAR__":
            self.terminal_output.delete("1.0", "end")
            return

        self.terminal_output.insert("end", text + "\n")
        self.terminal_output.see("end")
        self.terminal_output.configure(state="disabled")

    # ===================== NETWORK =====================

    def get_my_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip

    # ===================== RULE POPUPS =====================

    def open_new_rule_popup(self):
        """Open a popup window to create a new firewall rule."""
        popup = ctk.CTkToplevel(self)
        popup.geometry("300x550")
        popup.title("New Rule")

        entries = {}

        # Protocol — dropdown instead of free text so the user can't
        # type something invalid like "http"
        ctk.CTkLabel(popup, text="Protocol").pack(pady=(10, 0))
        protocol_menu = ctk.CTkOptionMenu(popup, values=["tcp", "udp", "icmp", "any"])
        protocol_menu.pack()
        entries["protocol"] = protocol_menu

        # Source / destination IPs — free text, empty means "any"
        for field in ["Source IP", "Destination IP"]:
            ctk.CTkLabel(popup, text=f"{field}  (leave blank for any)").pack(pady=(10, 0))
            entry = ctk.CTkEntry(popup)
            entry.pack()
            entries[field] = entry

        # Source / destination ports — free text, empty or 0 means "any"
        for field in ["Source Port", "Destination Port"]:
            ctk.CTkLabel(popup, text=f"{field}  (0 or blank for any)").pack(pady=(10, 0))
            entry = ctk.CTkEntry(popup)
            entry.pack()
            entries[field] = entry

        # Action — dropdown
        ctk.CTkLabel(popup, text="Action").pack(pady=(10, 0))
        action_menu = ctk.CTkOptionMenu(popup, values=["allow", "deny", "alert"])
        action_menu.pack()
        entries["action"] = action_menu

        # Error label (hidden until something goes wrong)
        error_label = ctk.CTkLabel(popup, text="", text_color="red")
        error_label.pack(pady=(5, 0))

        def submit():
            # Read values from the form
            protocol = entries["protocol"].get()
            src_ip   = entries["Source IP"].get().strip()
            dst_ip   = entries["Destination IP"].get().strip()
            action   = entries["action"].get()

            # Parse ports — default to 0 (wildcard) if empty
            raw_src_port = entries["Source Port"].get().strip()
            raw_dst_port = entries["Destination Port"].get().strip()

            try:
                src_port = int(raw_src_port) if raw_src_port else 0
                dst_port = int(raw_dst_port) if raw_dst_port else 0
            except ValueError:
                error_label.configure(text="Ports must be numbers.")
                return

            # Basic validation
            if src_port < 0 or src_port > 65535 or dst_port < 0 or dst_port > 65535:
                error_label.configure(text="Ports must be 0-65535.")
                return

            # Save to database
            createRule(protocol, src_ip, dst_ip, src_port, dst_port, action)

            # Refresh the rules table in the UI
            refresh_rule_view(self)
            popup.destroy()

        ctk.CTkButton(popup, text="Submit", command=submit).pack(pady=15)

    def open_edit_rule_popup(self, rule):
        """
        Open a popup window pre-filled with an existing rule's values
        so the user can edit and save changes.

        'rule' is a sqlite3.Row (dict-like) from the database.
        """
        popup = ctk.CTkToplevel(self)
        popup.geometry("300x550")
        popup.title(f"Edit Rule #{rule['rid']}")

        entries = {}

        # Protocol
        ctk.CTkLabel(popup, text="Protocol").pack(pady=(10, 0))
        protocol_menu = ctk.CTkOptionMenu(popup, values=["tcp", "udp", "icmp", "any"])
        protocol_menu.set(rule["protocol"])
        protocol_menu.pack()
        entries["protocol"] = protocol_menu

        # Source IP
        ctk.CTkLabel(popup, text="Source IP  (leave blank for any)").pack(pady=(10, 0))
        src_ip_entry = ctk.CTkEntry(popup)
        src_ip_entry.insert(0, rule["src_ip"] or "")
        src_ip_entry.pack()
        entries["src_ip"] = src_ip_entry

        # Destination IP
        ctk.CTkLabel(popup, text="Destination IP  (leave blank for any)").pack(pady=(10, 0))
        dst_ip_entry = ctk.CTkEntry(popup)
        dst_ip_entry.insert(0, rule["dst_ip"] or "")
        dst_ip_entry.pack()
        entries["dst_ip"] = dst_ip_entry

        # Source Port
        ctk.CTkLabel(popup, text="Source Port  (0 or blank for any)").pack(pady=(10, 0))
        src_port_entry = ctk.CTkEntry(popup)
        src_port_entry.insert(0, str(rule["src_port"] or 0))
        src_port_entry.pack()
        entries["src_port"] = src_port_entry

        # Destination Port
        ctk.CTkLabel(popup, text="Destination Port  (0 or blank for any)").pack(pady=(10, 0))
        dst_port_entry = ctk.CTkEntry(popup)
        dst_port_entry.insert(0, str(rule["dst_port"] or 0))
        dst_port_entry.pack()
        entries["dst_port"] = dst_port_entry

        # Action
        ctk.CTkLabel(popup, text="Action").pack(pady=(10, 0))
        action_menu = ctk.CTkOptionMenu(popup, values=["allow", "deny", "alert"])
        action_menu.set(rule["action"])
        action_menu.pack()
        entries["action"] = action_menu

        # Error label
        error_label = ctk.CTkLabel(popup, text="", text_color="red")
        error_label.pack(pady=(5, 0))

        def submit():
            protocol = entries["protocol"].get()
            src_ip   = entries["src_ip"].get().strip()
            dst_ip   = entries["dst_ip"].get().strip()
            action   = entries["action"].get()

            raw_src_port = entries["src_port"].get().strip()
            raw_dst_port = entries["dst_port"].get().strip()

            try:
                src_port = int(raw_src_port) if raw_src_port else 0
                dst_port = int(raw_dst_port) if raw_dst_port else 0
            except ValueError:
                error_label.configure(text="Ports must be numbers.")
                return

            if src_port < 0 or src_port > 65535 or dst_port < 0 or dst_port > 65535:
                error_label.configure(text="Ports must be 0-65535.")
                return

            # Update the existing rule in the database
            updateRule(rule["rid"], protocol, src_ip, dst_ip, src_port, dst_port, action)

            refresh_rule_view(self)
            popup.destroy()

        ctk.CTkButton(popup, text="Save Changes", command=submit).pack(pady=15)


# ================================================================== #
# Standalone functions (called from outside the class too)
# ================================================================== #

def start_app():
    app = App()

    # Start monitoring as soon as the app launches
    app.monitor.start()

    def on_close():
        app.monitor.stop()
        app.destroy()

    app.protocol("WM_DELETE_WINDOW", on_close)

    refresh_rule_view(app)
    app.mainloop()


def refresh_rule_view(app):
    """
    Clear and redraw the rules table on the Rules page.
    Each rule gets an Edit and Delete button.
    Also reloads the firewall so any rule changes take effect immediately.
    """
    app.monitor.reload_firewall()

    # Remove all widgets currently in the scrollable frame
    for widget in app.rules_frame.winfo_children():
        widget.destroy()

    # Column headers — each column gets weight=1 so they share
    # the available width equally and stretch to fill the frame.
    headers = ["ID", "Protocol", "Src IP", "Dst IP", "SPort", "DPort", "Action"]

    for col, header in enumerate(headers):
        app.rules_frame.columnconfigure(col, weight=1)
        ctk.CTkLabel(app.rules_frame, text=header,
                     font=("Roboto", 12, "bold")).grid(
                         row=0, column=col, padx=5, pady=5, sticky="ew")

    rules = readRules()

    for row_num, rule in enumerate(rules, start=1):
        values = [
            rule["rid"],
            rule["protocol"],
            rule["src_ip"] or "any",
            rule["dst_ip"] or "any",
            rule["src_port"] or "any",
            rule["dst_port"] or "any",
            rule["action"],
        ]

        for col, value in enumerate(values):
            ctk.CTkLabel(app.rules_frame, text=str(value)).grid(
                row=row_num, column=col, padx=5, pady=2, sticky="ew")

        # Edit button — opens the edit popup for this rule
        # We use a default argument (r=rule) in the lambda so each
        # button captures its own rule instead of all sharing the last one.
        ctk.CTkButton(
            app.rules_frame, text="Edit", width=50,
            command=lambda r=rule: app.open_edit_rule_popup(r)
        ).grid(row=row_num, column=7, padx=2, pady=2)

        # Delete button
        def make_delete(rid):
            def do_delete():
                deleteRule(rid)
                refresh_rule_view(app)
            return do_delete

        ctk.CTkButton(
            app.rules_frame, text="Delete", width=50,
            fg_color="#7d2a2a", hover_color="#5c1e1e",
            command=make_delete(rule["rid"])
        ).grid(row=row_num, column=8, padx=2, pady=2)


if __name__ == "__main__":
    start_app()
