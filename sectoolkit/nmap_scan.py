"""Utility to check for open ports using nmap if installed."""
import shutil
import subprocess
from typing import List, Dict, Any


def nmap_scan(host: str, ports: str = "1-1024") -> Dict[str, Any]:
    """Run nmap scan if nmap is available, parse basic output.
    
    Returns dict with keys: host, ports (list of open ports), error.
    """
    result = {"host": host, "ports": [], "error": None}
    if not shutil.which("nmap"):
        result["error"] = "nmap not installed"
        return result
    
    cmd = ["nmap", "-p", ports, "-T4", "-oG", "-", host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            result["error"] = proc.stderr.strip()
            return result
        for line in proc.stdout.splitlines():
            if line.startswith("Host:") and "Ports:" in line:
                parts = line.split("Ports:")
                ports_part = parts[1]
                for entry in ports_part.split(","):
                    port_info = entry.strip().split("/")
                    if len(port_info) >= 2 and port_info[1] == "open":
                        result["ports"].append(int(port_info[0]))
    except Exception as e:
        result["error"] = str(e)
    return result
