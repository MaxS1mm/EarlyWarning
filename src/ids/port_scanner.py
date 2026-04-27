"""
port_scanner.py

Educational port and vulnerability scanner.
Maps open ports against known Metasploitable 2 vulnerabilities so users
can see exactly why each open port is dangerous.

Now also does 'banner grabbing' — it connects to each open port and reads
the first message the service sends back. That message usually contains the
software name and version, which we compare against the known-vulnerable
versions from Metasploitable 2.
"""

import socket
import subprocess
import threading

# ------------------------------------------------------------------ #
# Metasploitable 2 vulnerability database
# Each entry: port -> short description of the vulnerability
# ------------------------------------------------------------------ #
METASPLOITABLE_VULNS = {
    21:    "FTP vsftpd 2.3.4 BACKDOOR: a smiley ':)' in the username "
           "triggers a shell listener on port 6200.",
    22:    "SSH OpenSSH 4.7p1: very old version with weak ciphers, commonly brute-forced.",
    23:    "Telnet: passwords sent in plaintext — anyone on the network can read them.",
    25:    "SMTP Postfix: configured as an open relay, can be abused to send spam.",
    53:    "DNS BIND 9.4.2: vulnerable to cache poisoning, zone transfers leak internal hostnames.",
    80:    "HTTP Apache 2.2.8: hosts DVWA, Mutillidae and phpMyAdmin — all intentionally vulnerable.",
    111:   "rpcbind: exposes RPC service list, used to enumerate NFS shares.",
    139:   "NetBIOS/Samba 3.0.20: username field allows shell command injection.",
    445:   "SMB/Samba 3.0.20: same usermap_script bug as port 139, gives root shell.",
    512:   "rexec: remote execution with no encryption.",
    513:   "rlogin: trusts .rhosts files, authentication can be bypassed.",
    514:   "rsh: remote shell, no password if .rhosts allows the client.",
    1099:  "Java RMI Registry: deserialisation attack can give remote code execution.",
    1524:  "Ingreslock BACKDOOR: connecting to this port drops you straight into a root shell.",
    2049:  "NFS: network filesystem exposed, may allow remote directory mounting.",
    2121:  "FTP ProFTPD 1.3.1: mod_copy lets anyone copy files without logging in.",
    3306:  "MySQL 5.0.51a: root account has NO password — full database access for anyone.",
    3632:  "distcc 1.x: compile jobs run as the daemon user — easy RCE.",
    5432:  "PostgreSQL 8.3: default credentials postgres/postgres, COPY command can run OS commands.",
    5900:  "VNC: password is literally 'password' — full graphical desktop access.",
    6000:  "X11: no access control, remote clients can read your screen and inject keystrokes.",
    6667:  "IRC UnrealIRCd 3.2.8.1 BACKDOOR: DEBUG3 command triggers a shell.",
    8009:  "Apache JServ / Tomcat AJP: remote file read / inclusion.",
    8180:  "Apache Tomcat manager: default credentials tomcat/tomcat, deploy a WAR to get RCE.",
    10000: "Webmin 1.485: default credentials, authenticated remote code execution.",
    57348: "Java RMI high port: random port opened by RMI, same deserialisation attack as port 1099.",
}

# ------------------------------------------------------------------ #
# The exact version strings that Metasploitable 2 shows in its banners.
#
# When we connect to a port, the service usually sends a greeting message
# (called a 'banner') that includes its name and version number.
# We search the banner for the string listed here.
#
# If the banner contains the string  -> version CONFIRMED vulnerable.
# If the banner does NOT contain it  -> different (possibly safe) version.
# If the port is not listed here     -> we have no way to check.
#
# An empty string ("") means just connecting to that port is proof enough
# (e.g. port 1524 instantly drops you into a root shell on Metasploitable 2).
# ------------------------------------------------------------------ #
VULNERABLE_VERSION_STRINGS = {
    21:    "vsFTPd 2.3.4",        # banner: "220 (vsFTPd 2.3.4)"
    22:    "OpenSSH_4.7p1",       # banner: "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1"
    25:    "Postfix",             # banner: "220 metasploitable.localdomain ESMTP Postfix"
    53:    "9.4.2",               # DNS version query returns "9.4.2"
    80:    "Apache/2.2.8",        # HTTP response header: "Server: Apache/2.2.8 (Ubuntu)"
    2121:  "ProFTPD 1.3.1",       # banner: "220 ProFTPD 1.3.1 Server"
    3306:  "5.0.51a",             # MySQL sends its version in the first packet
    3632:  "distcc",              # distcc identifies itself in its banner
    5432:  "8.3",                 # PostgreSQL sends its version in the startup error message
    5900:  "RFB 003.003",         # VNC banner: old protocol version = old vulnerable server
    6667:  "UnrealIRCd",          # IRC MOTD contains "UnrealIRCd"
    8180:  "Apache-Coyote/1.1",   # Tomcat HTTP response header
    10000: "MiniServ/0.01",       # Webmin banner
    1524:  "",                    # No version check needed — open port = backdoor
    6000:  "",                    # X11 banner is binary; being open is enough
    57348: "",                    # RMI high port — being open is enough
}

# ------------------------------------------------------------------ #
# Some services only reply after we send them a request first.
# This dict maps port -> the bytes we need to send to get a banner back.
# Ports not listed here send a banner immediately on connect.
# ------------------------------------------------------------------ #
SEND_PROBE = {
    80:   b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8180: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
}

# Ports to scan in a 'quick' scan — all known Metasploitable 2 ports
QUICK_PORTS = sorted(METASPLOITABLE_VULNS.keys())


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Connect to a port and read whatever text the service sends back.
    This text is called a 'banner' and usually contains the software
    name and version number.

    Returns the banner as a plain string.
    Returns an empty string if nothing came back or an error occurred.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Some services wait for us to say something first.
        # If we have a probe for this port, send it.
        probe = SEND_PROBE.get(port, b"")
        if probe:
            sock.sendall(probe)

        # Read up to 1024 bytes of the banner response.
        banner_bytes = sock.recv(1024)
        sock.close()

        # Convert the raw bytes to a readable string.
        # 'errors=ignore' skips any bytes that aren't valid UTF-8 text
        # (binary protocols like VNC mix binary and text).
        return banner_bytes.decode("utf-8", errors="ignore")

    except Exception:
        # Could not grab a banner (firewall, service too slow, etc.)
        return ""


def _check_version(port: int, banner: str):
    """
    Look for the known-vulnerable version string inside the banner text.

    Returns:
        True  — the banner contains the vulnerable version string
        False — the banner was read but the version string wasn't in it
        None  — we have no version string to check for this port
    """
    # If we don't have a version string for this port, we can't check it
    if port not in VULNERABLE_VERSION_STRINGS:
        return None

    version_str = VULNERABLE_VERSION_STRINGS[port]

    # An empty version string means just being open confirms it
    # (used for ports like 1524 where the backdoor is always present)
    if version_str == "":
        return True

    # Search the banner for our version string (case-insensitive so we
    # don't miss differences like "PostFix" vs "Postfix")
    return version_str.lower() in banner.lower()


def _scan_one_port(ip: str, port: int, timeout: float, results: dict):
    """
    Check whether one port is open. If it is, grab its banner and
    compare the version against the known-vulnerable Metasploitable 2 version.

    Stores a dict in results[port] with three fields:
        'open'          - True if the port accepted our connection
        'banner'        - the text the service sent back (may be empty)
        'version_match' - True/False/None (see _check_version)
    """
    entry = {"open": False, "banner": "", "version_match": None}

    try:
        # Step 1: quick connect test — does the port even accept connections?
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connected = sock.connect_ex((ip, port)) == 0
        sock.close()

        entry["open"] = connected

        if connected:
            # Step 2: grab the banner so we can check the version
            # Give it a little more time than the basic connect check
            banner = _grab_banner(ip, port, timeout=timeout + 1.0)
            entry["banner"] = banner

            # Step 3: compare the banner against the vulnerable version string
            entry["version_match"] = _check_version(port, banner)

    except Exception:
        pass  # Leave defaults: port treated as closed / version unknown

    results[port] = entry


def run_scan(ip: str, ports: list, print_func, timeout: float = 1.0):
    """
    Scan *ports* on *ip*.

    Uses one thread per port so all ports are checked at the same time —
    much faster than scanning one at a time.

    print_func is called to send output lines back to the terminal UI.
    """
    # Check if the host is reachable before scanning
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        if result.returncode != 0:
            print_func(f"Host {ip} is unreachable.")
            return
    except Exception:
        print_func(f"Host {ip} is unreachable.")
        return

    print_func(f"Scanning {ip} across {len(ports)} ports...")
    print_func("(Checking ports and grabbing service banners — may take a few seconds)")

    results = {}
    threads = []

    for port in ports:
        t = threading.Thread(target=_scan_one_port, args=(ip, port, timeout, results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # ---- Print results ----
    open_ports = sorted(p for p, entry in results.items() if entry["open"])

    print_func("")
    print_func("=" * 60)
    print_func(f"  Scan complete: {ip}")
    print_func("=" * 60)

    if not open_ports:
        print_func("  No open ports found.")
    else:
        for port in open_ports:
            entry        = results[port]
            vuln         = METASPLOITABLE_VULNS.get(port)
            version_match = entry["version_match"]

            if vuln:
                # Pick a status label based on whether the version matched
                if version_match is True:
                    status = "OPEN  *** VULNERABLE VERSION CONFIRMED ***"
                elif version_match is False:
                    status = "OPEN  [version does NOT match — may not be vulnerable]"
                else:
                    # No version string available for this port
                    status = "OPEN  [VULNERABLE — could not confirm version]"

                print_func(f"  PORT {port:<6} {status}")
                print_func(f"         Vulnerability: {vuln}")

                # Show what the service actually said so the user can see
                # the raw version string themselves
                if entry["banner"]:
                    first_line = entry["banner"].splitlines()[0].strip()
                    print_func(f"         Banner:        {first_line}")
                else:
                    print_func(f"         Banner:        (no banner received)")

                print_func("")
            else:
                print_func(f"  PORT {port:<6} OPEN")

        print_func(f"  {len(open_ports)} open port(s) found.")

    print_func("=" * 60)
