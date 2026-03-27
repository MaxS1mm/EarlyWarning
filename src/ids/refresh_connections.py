import time

def start_connection_display(monitor, ui_callback=None):
    def display():
        while True:
            connections = monitor.get_active_connections()

            if ui_callback:
                # Send to UI safely
                ui_callback(connections)
            else:
                # CLI fallback
                print("\nActive Connections\n")

                for key, data in connections:
                    proto, src, sport, dst, dport = key
                    print(f"{proto} {src}:{sport} -> {dst}:{dport} "
                          f"{data['state']} Packets:{data['packets']}")

            time.sleep(2)

    import threading
    threading.Thread(target=display, daemon=True).start()