import sys
import os
from src.db.db_utils import database_exists, initialize_database
from src.db.CRUD import createUser
from src.UI.home import start_app
import subprocess

# Paths
CIC_PYTHON = "/Users/maxsimanonok/Desktop/IDS/cic_venv/bin/python3.10"
CIC_FLOW = "/Users/maxsimanonok/Desktop/IDS/cic_venv/bin/cicflowmeter"
APP_PYTHON = "/Users/maxsimanonok/Desktop/IDS/.venv/bin/python"
APP_SCRIPT = "/Users/maxsimanonok/Desktop/IDS/src/UI/home.py"

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
    # Start cicflowmeter in the background
    if sys.platform.startswith("linux"):
        subprocess.Popen([CIC_PYTHON, CIC_FLOW, "-i", "eth0", "-c", "flows.csv"])
    else:
        subprocess.Popen([CIC_PYTHON, CIC_FLOW, "-i", "en0", "-cv", "flows.csv"])       
    # Start your app script in the other venv
    start_app()
    

if __name__ == "__main__":
    main()