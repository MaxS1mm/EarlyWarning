import tkinter, socket, time
import customtkinter as ctk
from src.db.CRUD import usernameExists, createUser, readUsername, createRule, readRules
from ..ids.flow_monitor import FlowMonitor
from src.ids.terminal_controller import TerminalController


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        my_ip = self.get_my_ip()

        self.title("Early Warning - An Intrusion Detection System")
        self.geometry("1000x750")


        self.monitor = FlowMonitor(alert_callback=lambda ip, data: self.after(0, self.log_alert, ip, data))
        self.terminal = TerminalController(
            monitor=self.monitor,
            print_func=self.terminal_print
        )
        self.updating = False

        # Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ===================== SIDEBAR =====================
        self.sidebar_frame = ctk.CTkFrame(self, width=160, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

        ctk.CTkLabel(self.sidebar_frame, text="EarlyWarning",
                     font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, padx=20, pady=(20, 10))

        username = readUsername()
        ctk.CTkLabel(self.sidebar_frame, text=username,
                     font=ctk.CTkFont(size=12, weight="bold")).grid(row=1, column=0, padx=20, pady=(0, 20))

        # Navigation buttons
        ctk.CTkButton(self.sidebar_frame, text="Connections",
                      command=lambda: self.show_frame("connections")).grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        ctk.CTkButton(self.sidebar_frame, text="Rules",
                      command=lambda: self.show_frame("rules")).grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        ctk.CTkButton(self.sidebar_frame, text="Terminal",
                      command=lambda: self.show_frame("terminal")).grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        
        ctk.CTkButton(self.sidebar_frame, text="Settings",
                      command=lambda: self.show_frame("settings")).grid(row=5, column=0, padx=20, pady=10, sticky="ew")

        # ===================== MAIN FRAMES =====================
        self.frames = {}

        for name in ["connections", "rules", "terminal", "settings"]:
            frame = ctk.CTkFrame(self)
            frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
            frame.grid_remove()
            self.frames[name] = frame

        # ===================== CONNECTIONS FRAME =====================
        conn = self.frames["connections"]

        ctk.CTkLabel(conn, text=f"Your IP: {my_ip}").pack(pady=10)

        self.connections_textbox = ctk.CTkTextbox(conn)
        self.connections_textbox.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkButton(conn, text="Start", command=self.start_monitoring).pack(pady=5)
        ctk.CTkButton(conn, text="Stop", command=self.stop_monitoring).pack(pady=5)

        # ===================== RULES FRAME =====================
        rules = self.frames["rules"]

        ctk.CTkButton(rules, text="Create New Rule",
                      command=self.open_new_rule_popup).pack(pady=10)

        self.rules_frame = ctk.CTkScrollableFrame(rules)
        self.rules_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # ===================== SETTINGS FRAME =====================
        settings = self.frames["settings"]

        # ===================== TERMINAL FRAME =====================
        terminal = self.frames["terminal"]

        self.terminal_output = ctk.CTkTextbox(terminal, wrap="word", fg_color="black", text_color="white")
        self.terminal_output.pack(fill="both", expand=True, padx=10, pady=10)

        self.terminal_input = ctk.CTkEntry(terminal)
        self.terminal_input.pack(fill="x", padx=10, pady=(0, 10))

        self.terminal_input.bind("<Return>", self.handle_terminal_input)

        # ===================== LOG PANEL =====================
        self.scrollable_frame = ctk.CTkScrollableFrame(self, label_text="Recent Logs")
        self.scrollable_frame.grid(row=1, column=1, padx=20, pady=10, sticky="nsew")

        # Show default frame
        self.show_frame("connections")

    def handle_terminal_input(self, event=None):
        raw = self.terminal_input.get()
        self.terminal_input.delete(0, "end")

        self.terminal_print(f"> {raw}")
        self.terminal.handle(raw)

    # ===================== NAVIGATION =====================
    def show_frame(self, name):
        for frame in self.frames.values():
            frame.grid_remove()
        self.frames[name].grid()

    # ===================== LOGGING =====================
    def log_alert(self, src_ip, data):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        msg = f"⚠️ Port scan from {src_ip} at {timestamp} | Ports: {len(data['ports'])}\n"

        ctk.CTkLabel(self.scrollable_frame, text=msg, anchor="w").pack(fill="x", padx=5, pady=2)

    # ===================== TERMINAL =====================
    def handle_terminal_input(self, event=None):
        raw = self.terminal_input.get()
        self.terminal_input.delete(0, "end")

        self.terminal_print(f"> {raw}")
        self.terminal.handle(raw)

    def terminal_print(self, text):
        if text == "__CLEAR__":
            self.terminal_output.delete("1.0", "end")
            return

        self.terminal_output.insert("end", text + "\n")
        self.terminal_output.see("end")

    # ===================== PARSING =====================
    def parse_command(self, raw_input):
        parts = raw_input.strip().split()
        if not parts:
            return None, []

        cmd = parts[0].lower()
        args = parts[1:]
        return cmd, args

    # ===================== OUTPUT =====================
    def print_line(self, text):
        self.terminal_output.insert("end", text + "\n")
        self.terminal_output.see("end")

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

    # ===================== MONITOR =====================
    def start_monitoring(self):
        self.monitor.start(iface="en0")
        self.updating = True
        self.update_ui()

    def stop_monitoring(self):
        self.monitor.stop()
        self.updating = False

    def update_ui(self):
        if not self.updating:
            return

        self.connections_textbox.delete("1.0", "end")
        connections = self.monitor.get_active_connections()

        for (proto, src, sport, dst, dport), data in connections:
            line = f"{proto} {src}:{sport} -> {dst}:{dport} {data['state']} Packets:{data['packets']}\n"
            self.connections_textbox.insert("end", line)

        self.after(1000, self.update_ui)

    # ===================== RULE POPUP =====================
    def open_new_rule_popup(self):
        popup = ctk.CTkToplevel(self)
        popup.geometry("250x500")
        popup.title("New Rule")

        entries = {}
        fields = ["Protocol", "Source IP", "Destination IP", "Source Port", "Destination Port"]

        for field in fields:
            ctk.CTkLabel(popup, text=field).pack()
            entry = ctk.CTkEntry(popup)
            entry.pack()
            entries[field] = entry

        action = ctk.CTkOptionMenu(popup, values=["allow", "deny", "alert"])
        action.pack()
        entries["Action"] = action

        def submit():
            data = {k: v.get() for k, v in entries.items()}
            createRule(data["Protocol"], data["Source IP"], data["Destination IP"],
                       int(data["Source Port"]), int(data["Destination Port"]), data["Action"])
            refresh_rule_view(self)
            popup.destroy()

        ctk.CTkButton(popup, text="Submit", command=submit).pack(pady=10)


def start_app():
    app = App()

    if not usernameExists():
        dialog = ctk.CTkInputDialog(text="Enter username:", title="User")
        createUser(dialog.get_input())

    def on_close():
        app.monitor.stop()
        app.destroy()

    app.protocol("WM_DELETE_WINDOW", on_close)

    refresh_rule_view(app)
    app.mainloop()


def refresh_rule_view(self):
    for widget in self.rules_frame.winfo_children():
        widget.destroy()

    headers = ["Protocol", "Src Port", "Dst Port", "Src IP", "Dst IP", "Action"]

    for col, header in enumerate(headers):
        ctk.CTkLabel(self.rules_frame, text=header, font=("Roboto", 12, "bold"))\
            .grid(row=0, column=col, padx=10, pady=5)

    rules = readRules()

    for row_id, rule in enumerate(rules, start=1):
        values = [rule["protocol"], rule["src_port"], rule["dst_port"],
                  rule["src_ip"], rule["dst_ip"], rule["action"]]

        for col_id, value in enumerate(values):
            ctk.CTkLabel(self.rules_frame, text=str(value))\
                .grid(row=row_id, column=col_id, padx=10, pady=2)


if __name__ == "__main__":
    start_app()