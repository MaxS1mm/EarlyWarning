import tkinter
import customtkinter as ctk
from src.db.CRUD import usernameExists, createUser, readUsername, createRule, readRules

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configure window
        self.title("Early Warning - An Intrusion Detection System")
        self.geometry(f"{1600}x800")

        # Configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # Create sidebar frame with widgets
        self.sidebar_frame = ctk.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="EarlyWarning", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        username = readUsername()
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text=username, font=ctk.CTkFont(size=12, weight="bold"))
        self.logo_label.grid(row=1, column=0, padx=20, pady=(20, 10))

        # self.sidebar_button_1 = ctk.CTkButton(self.sidebar_frame, text="Settings")
        # self.sidebar_button_1.grid(row=2, column=0, padx=20, pady=10)

        # self.appearance_mode_label = ctk.CTkLabel(self., text="Appearance Mode:", anchor="w")
        # self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))
        # self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark"],
        #                                                                 command=self.change_appearance_mode_event)
        # self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 10))

        # Create tabview
        self.tabview = ctk.CTkTabview(self, width=250)
        self.tabview.grid(row=0, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.tabview.add("Current Connections")
        self.tabview.add("Rules")
        self.tabview.add("Settings")

        # current connections tab
        self.tabview.tab("Current Connections").grid_columnconfigure(0, weight=1)
        self.label_tab_1 = ctk.CTkLabel(self.tabview.tab("Current Connections"), text="Protocol: Src Port: Dest Port: Src IP: Dest IP: ")
        self.label_tab_1.grid(row=0, column=0, padx=20, pady=20)

        # Rules tab
        self.tabview.tab("Rules").grid_columnconfigure(0, weight=1)
        self.new_rule_button = ctk.CTkButton(self.tabview.tab("Rules"), text="Create New Rule", command=self.open_new_rule_popup)
        self.new_rule_button.grid(row=0, column=0, padx=20, pady=10)

        # Settings tab
        self.tabview.tab("Settings").grid_columnconfigure(0, weight=1)

        #Change appearance setting
        self.appearance_mode_label = ctk.CTkLabel(self.tabview.tab("Settings"), text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.tabview.tab("Settings"), values=["Light", "Dark"], command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 10))


        #Rule Entries & configuration
        self.rules_frame = ctk.CTkScrollableFrame(self.tabview.tab("Rules"))
        for col in range(6):
            self.rules_frame.grid_columnconfigure(col, weight=1)
        self.rules_frame.grid(
            row=2,
            column=0,
            columnspan=4,
            sticky="nsew",
            padx=10,
            pady=10
        )
        self.grid_rowconfigure(2, weight=0)
        self.grid_columnconfigure(0, weight=0)
    
        # Log frame
        self.scrollable_frame = ctk.CTkScrollableFrame(self, label_text="Recent Logs")
        self.scrollable_frame.grid(row=1, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.scrollable_frame.grid_columnconfigure(0, weight=1)


    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    def open_new_rule_popup(self):
        # Create popup window
        popup = ctk.CTkToplevel(self)
        popup.geometry("250x500")
        popup.title("New Rule Information")
        
        popup.grab_set()  # Prevent interaction with main window
        popup.focus()     # Focus on the popup
        
        # Input fields
        entries = {}
        fields = ["Protocol", "Source IP", "Destination IP", "Source Port", "Destination Port"]
        for field in fields:
            label = ctk.CTkLabel(popup, text=field + ":")
            label.pack(pady=(10, 2))
            entry = ctk.CTkEntry(popup)
            entry.pack(pady=(0, 5))
            entries[field] = entry

        label = ctk.CTkLabel(popup, text="Action :")
        label.pack(pady=(10, 2))
        action_menu_entry = ctk.CTkOptionMenu(popup, values=["allow", "deny", "alert"])
        action_menu_entry.pack(pady=(0, 5))
        entries["Action"] = action_menu_entry
        
        # Submit button function
        def submit_rule():
            # Collect all inputs
            data = {field: entry.get() for field, entry in entries.items()}
            createRule(data["Protocol"], data["Source IP"], data["Destination IP"], int(data["Source Port"]), int(data["Destination Port"]), data["Action"])
            refresh_rule_view(self)
            popup.destroy()  # Close popup
        
        submit_btn = ctk.CTkButton(popup, text="Submit", command=submit_rule)
        submit_btn.pack(pady=15)
        
        # Wait until the popup is closed
        popup.wait_window()

def start_app():
    app = App()
    
    # First time opening app, create username and store in database.
    if(usernameExists() == False):
        dialog = ctk.CTkInputDialog(text="Enter a username:", title="Create a Username")
        user_input = dialog.get_input() # This opens the dialog and waits for user input
        createUser(user_input)

    refresh_rule_view(app)
    app.mainloop()

def refresh_rule_view(self):
    # Clear old widgets
    for widget in self.rules_frame.winfo_children():
        widget.destroy()

    headers = ["Protocol", "Src Port", "Dst Port", "Src IP", "Dst IP", "Action"]

    # Header row
    for col, header in enumerate(headers):
        ctk.CTkLabel(
            self.rules_frame,
            text=header,
            font=("Roboto", 12, "bold")
        ).grid(
            row=0,
            column=col,
            padx=10,
            pady=5,
            sticky="w"
        )

    rules = readRules()

    # Data rows
    for row_id, rule in enumerate(rules, start=1):
        values = [
            rule["protocol"],
            rule["src_port"],
            rule["dst_port"],
            rule["src_ip"],
            rule["dst_ip"],
            rule["action"]
        ]
        for col_id, value in enumerate(values):
            ctk.CTkLabel(
                self.rules_frame,
                text=str(value),
                anchor="w"
            ).grid(
                row=row_id,
                column=col_id,
                padx=10,
                pady=2,
                sticky="w"
            )

if __name__ == "__main__":
    start_app()