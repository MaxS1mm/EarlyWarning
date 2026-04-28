from .db_utils import get_connection
import sqlite3


### Create rules

def createRule(protocol, src_ip, dst_ip, src_port, dst_port, action):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO rules (protocol, src_ip, dst_ip, src_port, dst_port, action) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (protocol, src_ip, dst_ip, src_port, dst_port, action)
    )

    conn.commit()
    conn.close()


### read rules 

def readRules():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM rules")
    rules = cursor.fetchall()

    conn.close()

    if not rules:
        return []

    return rules


def readRuleById(rid):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM rules WHERE rid = ?", (rid,))
    rule = cursor.fetchone()

    conn.close()
    return rule


### update rules

def updateRule(rid, protocol, src_ip, dst_ip, src_port, dst_port, action):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE rules "
        "SET protocol = ?, src_ip = ?, dst_ip = ?, src_port = ?, dst_port = ?, action = ? "
        "WHERE rid = ?",
        (protocol, src_ip, dst_ip, src_port, dst_port, action, rid)
    )

    conn.commit()
    conn.close()


## delete rules

def deleteRule(rid):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM rules WHERE rid = ?", (rid,))

    conn.commit()
    conn.close()


### create logs

def createLog(timestamp, message):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO logs (timestamp, message) VALUES (?, ?)",
        (timestamp, message)
    )

    conn.commit()
    conn.close()


### read logs

def readLogs():
    """Return all log entries ordered oldest to newest."""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM logs ORDER BY lid ASC")
    logs = cursor.fetchall()

    conn.close()
    return logs
