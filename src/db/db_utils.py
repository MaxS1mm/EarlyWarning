import sqlite3
from pathlib import Path
import platform

def get_db_path() -> Path:
    if platform.system() == "Linux":
        # return Path("/etc/firewall_ids/rules.db")
        return Path(__file__).resolve().parents[2] / "data" / "rules.db"
    else:
        return Path(__file__).resolve().parents[2] / "data" / "rules.db"

def database_exists() -> bool:
    return get_db_path().exists()


def initialize_database():
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rules (
        rid INTEGER PRIMARY KEY AUTOINCREMENT,
        protocol TEXT CHECK(protocol IN ('tcp','udp','icmp','any')) NOT NULL,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        action TEXT CHECK(action IN ('allow','deny','alert')) NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        lid INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        message TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()

def valid_action(action: str):
    if(action == "allow" or action == "deny" or action == "alert"):
        return True
    else: 
        return False
    
def get_connection():
    return sqlite3.connect(get_db_path())