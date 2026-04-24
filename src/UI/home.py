import tkinter, socket, time
import customtkinter as ctk
from src.db.CRUD import createRule, readRules, updateRule, deleteRule
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
            refresh_rules_func=lambda: refresh_rule_view(self)
        )
        # Layout: sidebar | main content
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ===================== SIDEBAR =====================
        self.sidebar_frame = ctk.CTkFrame(self, width=160, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)

        ctk.CTkLabel(self.sidebar_frame, text="EarlyWarning",
                     font=ctk.CTkFont(size=20, weight="bold")).grid(
                         row=0, column=0, padx=20, pady=(20, 10))

        ctk.CTkButton(self.sidebar_frame, text="Logs",
                      command=lambda: self.show_frame("logs")).grid(
                          row=2, column=0, padx=20, pady=10, sticky="ew")

        ctk.CTkButton(self.sidebar_frame, text="Rules",
                      command=lambda: self.show_frame("rules")).grid(
                          row=3, column=0, padx=20, pady=10, sticky="ew")

        ctk.CTkButton(self.sidebar_frame, text="Terminal",
                      command=lambda: self.show_frame("terminal")).grid(
                          row=4, column=0, padx=20, pady=10, sticky="ew")

        ctk.CTkButton(self.sidebar_frame, text="Settings",
                      command=lambda: self.show_frame("settings")).grid(
                          row=5, column=0, padx=20, pady=10, sticky="ew")

        # ===================== MAIN FRAMES =====================
        self.frames = {}

        for name in ["logs", "rules", "terminal", "settings"]:
            frame = ctk.CTkFrame(self)
            frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
            frame.grid_remove()
            self.frames[name] = frame

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

        ctk.CTkButton(logs_frame, text="Clear Logs",
                      command=self._clear_logs).pack(pady=(0, 10))

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

        # ===================== SETTINGS FRAME =====================
        # (empty for now)

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

        if alert_type == "firewall_block":
            rule = data.get("rule") or {}
            line = (f"[{timestamp}]  FIREWALL BLOCK  {src_ip}"
                    f"  ->  proto={rule.get('protocol','?')} "
                    f"dst={rule.get('dst_ip','?')}:{rule.get('dst_port','?')}\n")

        elif alert_type == "firewall_alert":
            rule = data.get("rule") or {}
            line = (f"[{timestamp}]  FIREWALL ALERT  {src_ip}"
                    f"  ->  proto={rule.get('protocol','?')} "
                    f"dst={rule.get('dst_ip','?')}:{rule.get('dst_port','?')}\n")

        else:
            scan_type  = data.get("scan_type", "SCAN")
            total      = data.get("total_ports", len(data.get("ports", [])))
            desc       = data.get("description", "")
            line = (f"[{timestamp}]  PORT SCAN [{scan_type}]  from {src_ip}"
                    f"  |  {total} port(s) probed\n"
                    f"            {desc}\n")

        self.log_textbox.insert("end", line)
        self.log_textbox.see("end")

    def _clear_logs(self):
        self.log_textbox.delete("1.0", "end")

    # ===================== TERMINAL =====================

    def handle_terminal_input(self, event=None):
        raw = self.terminal_input.get()
        self.terminal_input.delete(0, "end")
        self.terminal_print(f"> {raw}")
        self.terminal.handle(raw)

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

    # ===================== SETTINGS =====================

    def change_appearance_mode_event(self, new_mode: str):
        ctk.set_appearance_mode(new_mode)

    # ===================== RULE POPUPS =====================

    def open_new_rule_popup(self):
        """Open a popup window to create a new firewall rule."""
        popup = ctk.CTkToplevel(self)
        popup.geometry("300x450")
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
        popup.geometry("300x450")
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
    """
    # Remove all widgets currently in the scrollable frame
    for widget in app.rules_frame.winfo_children():
        widget.destroy()

    # Column headers
    headers = ["ID", "Protocol", "Src IP", "Dst IP", "SPort", "DPort", "Action", "", ""]

    for col, header in enumerate(headers):
        ctk.CTkLabel(app.rules_frame, text=header,
                     font=("Roboto", 12, "bold")).grid(
                         row=0, column=col, padx=5, pady=5)

    rules = readRules()

    for row_num, rule in enumerate(rules, start=1):
        # Show each field in its own column
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
                row=row_num, column=col, padx=5, pady=2)

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
