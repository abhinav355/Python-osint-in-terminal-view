# OSINT Lab

A lightweight OSINT toolkit for researching publicly available information.

OSINT Lab brings common reconnaissance and OSINT tasks into one terminal-based tool, making it easier to investigate usernames, domains, IP addresses, DNS records, archived pages, and other publicly available information.

## Features

* Username searches
* Email investigation
* Phone number checks
* GitHub lookups
* IP information
* Domain information
* WHOIS lookups
* DNS reconnaissance
* Wayback Machine searches
* HTTP header inspection
* Port checking
* MAC address vendor lookup
* Search-engine dorks
* HTML report generation
* Local findings and logging

## Installation

### Windows EXE

The packaged Windows version does not require Python to be installed.

Download `OSINT-Lab.exe` and run it from Windows.

### Python Source

If you are running the source code directly, install the required dependency:

```bash
pip install requests
```

Then run:

```bash
python osint_lab.py
```

## Usage

Start OSINT Lab and use:

```text
help
```

to view the available commands.

Examples:

```text
username example
email example@example.com
github example
ip 8.8.8.8
domain example.com
dns example.com
whois example.com
wayback example.com
headers https://example.com
portscan example.com
mac 00:11:22:33:44:55
dorks example.com
```

For a broader reconnaissance workflow:

```text
recon example.com
```

## Reports

OSINT Lab can generate HTML reports containing findings collected during an investigation.

Reports can be opened in a normal web browser and stored locally for later reference.

## Requirements

### EXE

* Windows 10 or newer
* Internet connection for online lookups
* No Python installation required

### Source

* Python 3
* `requests`

## Legal and Responsible Use

OSINT Lab is intended for legal and authorized research.

Only investigate accounts, domains, devices, systems, or information when you have permission or when the activity is otherwise lawful.

The tool is designed around publicly available information and is not intended to bypass authentication, access private accounts, or break into systems.

You are responsible for how you use the software.

## Project Structure

A typical release can look like:

```text
OSINT-Lab/
├── OSINT-Lab.exe
├── README.md
└── reports/
```

## Version

**OSINT Lab v4.1**

A practical command-line OSINT toolkit focused on useful reconnaissance without unnecessary interface clutter.

## Author

Built by **Abhinav**.
