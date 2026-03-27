import sys
import os
from src.db.db_utils import database_exists, initialize_database
from src.db.CRUD import createUser
from src.UI.home import start_app

if os.geteuid() != 0:
    print("Restarting with sudo...")
    os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    
def ensure_database():
    if not database_exists():
        print("[*] Database not found, initializing...")
        initialize_database()

def check_privileges():
    if sys.platform.startswith("linux") and os.geteuid() != 0:
        print("⚠️  Warning: Not running as root. Some features may not work.")  

def main():
    check_privileges()
    ensure_database()
    start_app()

if __name__ == "__main__":
    main()