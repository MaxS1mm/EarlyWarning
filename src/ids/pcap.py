import subprocess

def start_cicflowmeter():
    command = [
        "sudo",
        "cic_env/bin/cicflowmeter",
        "-i", "eth0",
        "-c", "flows.csv"
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return process