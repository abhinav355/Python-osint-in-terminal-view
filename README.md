# OSINT Lab

**A lightweight OSINT toolkit for researching publicly available information.**

OSINT Lab is a command-line tool built for quick reconnaissance and investigation using information that is already publicly accessible on the internet.

It brings several common OSINT tasks into one place, so you don't have to keep opening twelve browser tabs just to check a username, domain, IP, DNS records, or archived pages.

---

## What it can do

OSINT Lab currently includes tools for:

* Username searches across multiple platforms
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
* Local findings and report logging

The main interface is intentionally terminal-based. No giant dashboard, no 47 buttons pretending to be innovation.

---

## Getting Started

### Using the EXE

If you downloaded the release version, you don't need Python installed.

Run:

```text
OSINT-Lab.exe
```

A terminal window will open and the OSINT Lab interface will start.

### Running from Python

If you're running the source code instead:

```bash
pip install requests
python osint_lab.py
```

---

## Basic Usage

Start the program and use:

```text
help
```

to see the available commands.

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

You can also use:

```text
recon example.com
```

for a broader reconnaissance workflow.

---

## Reports

OSINT Lab can generate HTML reports containing the information collected during an investigation.

Reports are designed to be readable in a normal web browser and can be kept as local investigation records.

The program also keeps local logging information while it runs.

---

## Requirements

### EXE version

For the packaged Windows version:

* Windows 10 or newer
* Internet connection for online lookups
* No Python installation required

### Source version

For running the Python source:

* Python 3
* `requests`

Install the dependency with:

```bash
pip install requests
```

---

## Important

OSINT Lab is intended for **legal and authorized research**.

Only investigate information, accounts, domains, devices, or systems when you have permission or when the activity is otherwise lawful.

This tool is designed around publicly available information. It is not intended to bypass authentication, break into accounts, or access private data.

You are responsible for how you use the software.

---

## Project Structure

A typical release looks like:

```text
OSINT-Lab/
│
├── OSINT-Lab.exe
├── README.txt
└── reports/
```

The executable contains the Python runtime and required Python dependencies, allowing the program to run on supported Windows machines without installing Python separately.

---

## Version

**OSINT Lab v4.1**

Built as a lightweight, practical OSINT toolkit with a focus on getting useful information quickly without turning the interface into a spaceship cockpit.

---

## Credits

Built by **Abhinav**.

If you find a bug, something breaks, or a lookup behaves strangely, keep the error output. That's usually much more useful than saying "bro it doesn't work."
