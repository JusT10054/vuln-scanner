"""
scanner.py
----------
Runs Nmap service/version detection scans and parses the resulting
XML into a simple structure the rest of the tool can work with.

Deliberately uses `subprocess` + Python's built-in XML parser instead
of the python-nmap library, so the only external dependency is the
`nmap` binary itself.
"""

import subprocess
import shutil
import sys
import xml.etree.ElementTree as ET


def run_nmap_scan(target: str, ports: str = "1-1000") -> str:
    """Run `nmap -sV` against a target and return the raw XML output as a string."""
    if shutil.which("nmap") is None:
        print("[!] nmap is not installed or not on PATH. Install it with:\n"
              "    sudo apt install nmap   (Debian/Kali/Ubuntu)\n"
              "    brew install nmap       (macOS)")
        sys.exit(1)

    cmd = ["nmap", "-sV", "-p", ports, "-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Nmap failed: {e.stderr}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] Nmap scan timed out after 10 minutes.")
        sys.exit(1)

    return result.stdout


def load_xml_file(path: str) -> str:
    """Read a previously saved Nmap XML file (offline / demo mode)."""
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"[!] File not found: {path}")
        sys.exit(1)


def parse_nmap_xml(xml_data: str):
    """
    Parse Nmap XML output into a list of hosts, each with a list of
    services that have identifiable product/version info.

    Returns:
        [
            {
                "ip": "192.168.1.10",
                "hostname": "metasploitable.local" or "",
                "services": [
                    {"port": "21", "protocol": "tcp", "service": "ftp",
                     "product": "vsftpd", "version": "2.3.4"},
                    ...
                ]
            },
            ...
        ]
    """
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        print(f"[!] Could not parse Nmap XML: {e}")
        sys.exit(1)

    hosts = []
    for host_el in root.findall("host"):
        # Skip hosts that were down / not scanned
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_el = host_el.find("address")
        ip = addr_el.get("addr") if addr_el is not None else "unknown"

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        services = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                if service_el is None:
                    continue

                product = service_el.get("product", "").strip()
                version = service_el.get("version", "").strip()

                # Only keep entries where Nmap actually fingerprinted a product/version
                # -- that's what we can meaningfully match against CVEs.
                if not product and not version:
                    continue

                services.append({
                    "port": port_el.get("portid"),
                    "protocol": port_el.get("protocol"),
                    "service": service_el.get("name", "unknown"),
                    "product": product,
                    "version": version,
                })

        hosts.append({"ip": ip, "hostname": hostname, "services": services})

    return hosts
