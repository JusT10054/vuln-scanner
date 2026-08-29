# Custom Vulnerability Scanner

A Python tool that wraps Nmap's service/version detection and cross-references
the results against the **NVD (National Vulnerability Database)** CVE feed to
automatically flag known vulnerabilities on a target — turning a raw port
scan into a prioritized, report-ready vulnerability assessment.

Built as a portfolio project to demonstrate scripting + offensive-security
fundamentals: reconnaissance, service fingerprinting, vulnerability
intelligence, and reporting.

## How it works

1. **Scan** — runs `nmap -sV` against a target (or loads a saved scan file)
   to fingerprint open ports and service versions.
2. **Parse** — extracts product + version strings from the Nmap XML output.
3. **Enrich** — queries the NVD API v2.0 for each unique product/version,
   pulling matching CVEs and their CVSS score/severity.
4. **Report** — outputs a console summary, a machine-readable JSON file,
   and a styled HTML report with color-coded severity.

## Requirements

- Python 3.8+
- [Nmap](https://nmap.org/) installed and on your `PATH`
  - Debian/Kali/Ubuntu: `sudo apt install nmap`
  - macOS: `brew install nmap`
- Python packages: `pip install -r requirements.txt`
- Internet access to `services.nvd.nist.gov` (the live CVE lookups need this;
  the Nmap scan itself does not)

## Usage

```bash
# Basic scan against a target you own/are authorized to test
python main.py 192.168.56.101

# Custom port range, output only JSON
python main.py 192.168.56.101 -p 1-65535 --format json

# Faster CVE lookups with a free NVD API key
# (raises the rate limit from 5 req/30s to 50 req/30s)
python main.py 192.168.56.101 --api-key YOUR_NVD_API_KEY

# Offline / demo mode — parse a saved Nmap XML scan, no live scanning needed
python main.py --offline-xml sample_scan.xml
```

Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key
(optional, but recommended if you're scanning more than a few services).

### Output

- `vuln_report.json` — full structured findings (host → service → CVE list)
- `vuln_report.html` — styled report with severity badges, open it in any browser
- Console output — quick-look summary while the scan runs

## Try it safely

Don't point this at systems you don't own or have explicit permission to
test. For practice, spin up a deliberately vulnerable target in an isolated
lab, e.g.:

- [Metasploitable2](https://sourceforge.net/projects/metasploitable/) — a VM
  loaded with known-vulnerable services (this is what `sample_scan.xml` in
  this repo was modeled on)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — for
  web-layer testing (pairs well with a separate web app scanner)

## Project structure

```
vuln_scanner/
├── main.py           # CLI entry point
├── scanner.py         # Nmap execution + XML parsing
├── cve_lookup.py       # NVD API queries, caching, rate-limiting
├── report.py          # Console / JSON / HTML report generation
├── sample_scan.xml    # Example Nmap XML for offline/demo mode
└── requirements.txt
```

## Known limitations (worth mentioning in interviews)

- Matching is keyword-based (`product + version` sent to NVD's
  `keywordSearch`), not CPE-based — this is simpler to implement but can
  produce false positives/negatives compared to strict CPE matching.
  A natural next step would be resolving each service to a proper CPE
  string via NVD's CPE dictionary before querying CVEs.
- NVD's public rate limit (5 req/30s without a key) makes scanning many
  services slow; the tool caches repeated product/version lookups to
  reduce redundant calls, but a large scan will still take time.
- Only flags **known** CVEs for the fingerprinted version — it doesn't
  detect zero-days or misconfigurations the way a full vulnerability
  scanner (Nessus/OpenVAS) would.

## Author

Jash Thakar
