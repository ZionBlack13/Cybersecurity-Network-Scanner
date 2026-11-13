
# Cybersecurity Network Scanner

A Python-based cybersecurity tool designed to discover hosts, scan network ports, identify services, search for potential CVE matches, and generate security assessment reports.

## Features

- Network host discovery
- TCP port scanning
- Service and version identification
- NVD CVE keyword lookup
- IP address and network validation
- JSON security reports
- HTML security dashboards
- Automated unit testing

## Technologies

- Python 3
- Kali Linux
- Nmap
- NVD API
- Pytest
- HTML and CSS

## Installation

Clone the repository and navigate to the project directory.

Create a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project dependencies.

## Usage

Scan localhost:

```bash
python main.py --target 127.0.0.1/32 --ports 1-1024
```

Scan a local test service:

```bash
python main.py --target 127.0.0.1/32 --ports 8000
```

Only scan systems you own or have permission to assess.

## Testing

```bash
python -m pytest -v
```

## Reports

Reports are generated in the `reports/` directory.

Supported formats:

- JSON
- HTML

CVE results are unverified keyword matches and should not be treated as confirmed vulnerabilities.

## Future Improvements

- CVE matching accuracy
- Vulnerability severity scoring
- Improved reporting dashboard
- Expanded automated testing
- Web-based user interface

## Author

Zion Black
