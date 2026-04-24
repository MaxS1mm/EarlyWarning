from .db_utils import get_connection
import sqlite3


# ------------------------------------------------------------------ #
# Rules — Create
# ------------------------------------------------------------------ #

def createRule(protocol, src_ip, dst_ip, src_port, dst_port, action):
    """
    Insert a new firewall rule into the database.

    protocol : str  – "tcp", "udp", "icmp", or "any"
    src_ip   : str  – source IP address, or "" / "any" for wildcard
    dst_ip   : str  – destination IP address, or "" / "any" for wildcard
    src_port : int  – source port number, or 0 for wildcard
    dst_port : int  – destination port number, or 0 for wildcard
    action   : str  – "allow", "deny", or "alert"
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO rules (protocol, src_ip, dst_ip, src_port, dst_port, action) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (protocol, src_ip, dst_ip, src_port, dst_port, action)
    )

    conn.commit()
    conn.close()


# ------------------------------------------------------------------ #
# Rules — Read
# ------------------------------------------------------------------ #

def readRules():
    """
    Return all firewall rules as a list of sqlite3.Row objects.
    Each row behaves like a dict so you can do row["protocol"], etc.
    Returns an empty list if there are no rules.
    """
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
    """
    Return a single rule by its rid.  Returns None if not found.
    """
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM rules WHERE rid = ?", (rid,))
    rule = cursor.fetchone()

    conn.close()
    return rule


# ------------------------------------------------------------------ #
# Rules — Update
# ------------------------------------------------------------------ #

def updateRule(rid, protocol, src_ip, dst_ip, src_port, dst_port, action):
    """
    Update an existing rule.  'rid' is the row ID of the rule to change.
    All other parameters replace the old values.
    """
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


# ------------------------------------------------------------------ #
# Rules — Delete
# ------------------------------------------------------------------ #

def deleteRule(rid):
    """Delete a rule from the database by its row ID."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM rules WHERE rid = ?", (rid,))

    conn.commit()
    conn.close()
