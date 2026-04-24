import sys
import os

def ensure_root():
    if os.geteuid() != 0:
        print("Root privileges required. Restarting with sudo...")
        try:
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except Exception as e:
            print(f"Failed to obtain root privileges: {e}")
            sys.exit(1)

def main():
    ensure_root()

    from src.db.db_utils import database_exists, initialize_database
    from src.UI.home import start_app

    if not database_exists():
        print("[*] Database not found, initializing...")
        initialize_database()

    start_app()

if __name__ == "__main__":
    main()