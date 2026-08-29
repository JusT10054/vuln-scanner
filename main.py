#!/usr/bin/env python3
"""
Custom Vulnerability Scanner
============================
Wraps Nmap service/version detection and cross-references the results
against the NVD (National Vulnerability Database) CVE feed to flag
known vulnerabilities on a target.

Usage:
    python main.py 192.168.1.10
    python main.py 192.168.1.10 -p 1-1000 --format both
    python main.py --offline-xml sample_scan.xml     # parse a saved scan, no live nmap needed
    python main.py 192.168.1.10 --api-key YOUR_NVD_KEY

Author: Jash Thakar
"""

import argparse
import sys
import time

from scanner import run_nmap_scan, parse_nmap_xml, load_xml_file
from cve_lookup import CVELookup
from report import build_report_data, print_console_report, write_json_report, write_html_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan a target with Nmap and flag known CVEs for detected service versions."
    )
    parser.add_argument("target", nargs="?", help="Target IP/hostname to scan (skip if using --offline-xml)")
    parser.add_argument("-p", "--ports", default="1-1000",
                         help="Port range to scan, e.g. '1-1000' or '22,80,443' (default: 1-1000)")
    parser.add_argument("--offline-xml", dest="offline_xml", default=None,
                         help="Parse an existing Nmap XML file instead of running a live scan")
    parser.add_argument("--api-key", dest="api_key", default=None,
                         help="NVD API key (optional, raises the request rate limit from 5/30s to 50/30s)")
    parser.add_argument("--max-cves", dest="max_cves", type=int, default=8,
                         help="Max CVEs to keep per service (sorted by severity, default: 8)")
    parser.add_argument("--format", choices=["console", "json", "html", "both"], default="both",
                         help="Output format (default: both = console + json + html)")
    parser.add_argument("--output", default="vuln_report",
                         help="Base filename for report output (default: vuln_report)")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.target and not args.offline_xml:
        print("[!] You must supply a target IP/hostname or --offline-xml <file>.")
        sys.exit(1)

    # --- Step 1: get an Nmap XML scan result, live or from file ---
    if args.offline_xml:
        print(f"[*] Loading Nmap results from {args.offline_xml} (offline mode)")
        xml_data = load_xml_file(args.offline_xml)
    else:
        print(f"[*] Scanning {args.target} (ports {args.ports}) with Nmap -sV ...")
        t0 = time.time()
        xml_data = run_nmap_scan(args.target, args.ports)
        print(f"[*] Scan complete in {time.time() - t0:.1f}s")

    # --- Step 2: parse services/versions out of the scan ---
    hosts = parse_nmap_xml(xml_data)
    total_services = sum(len(h["services"]) for h in hosts)
    print(f"[*] Found {len(hosts)} host(s), {total_services} service(s) with version info")

    if total_services == 0:
        print("[!] No versioned services detected — nothing to check against CVE feed.")
        sys.exit(0)

    # --- Step 3: look up CVEs for each unique product/version ---
    lookup = CVELookup(api_key=args.api_key)
    print("[*] Querying NVD for known CVEs (this respects NVD rate limits, so it may take a bit)...")
    findings = lookup.enrich_hosts(hosts, max_cves=args.max_cves)

    # --- Step 4: build + emit the report ---
    report_data = build_report_data(findings)

    if args.format in ("console", "both"):
        print_console_report(report_data)
    if args.format in ("json", "both"):
        path = write_json_report(report_data, f"{args.output}.json")
        print(f"[*] JSON report written to {path}")
    if args.format in ("html", "both"):
        path = write_html_report(report_data, f"{args.output}.html")
        print(f"[*] HTML report written to {path}")


if __name__ == "__main__":
    main()
