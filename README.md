```markdown
# Asset Monitoring Script

This script allows you to monitor the status and perform various checks on registered hosts.

## Features

- Register hosts by providing their IP address, domain name, and port numbers.
- Perform the following checks on registered hosts:
  - nslookup: Look up the IP address for a domain name.
  - dig: Perform a DNS query for a domain name.
  - whois lookup: Retrieve WHOIS information for a domain name.
  - DNS lookup: Retrieve the fully qualified domain name for an IP address.
  - nmap scan: Perform a port scan on an IP address.
- Display the results of each check for registered hosts.
- Color-coded status indicators for hosts based on scan results.

## Requirements

- Python 3.6 or higher
- Dependencies: `dns`, `whois`, `tkinter`

## Usage

1. Clone the repository or download the source code.
2. Install the dependencies using pip:

```
pip install dns whois
```

3. Run the script:

```
python main.py
```

4. The GUI window will open, allowing you to perform host checks and monitor the results.

## Adding Hosts

To add hosts for monitoring:

1. Click on the "Add Host" button.
2. Enter the IP address, domain name, and port numbers (comma-separated) for the host.
3. Click "Add" to register the host.
4. The registered host will be displayed in the list.

## Start Scanning

To start scanning the registered hosts:

1. Click on the "Start Scanning" button.
2. The script will perform checks (nslookup, dig, whois lookup, DNS lookup, and nmap scan) on each host.
3. The results will be displayed in the output section.
4. The host list will be updated with color-coded status indicators based on the scan results.

## License

This project is licensed under the [MIT License](LICENSE).
```
