# Created by Angelis Pseftis


import socket
import subprocess
import json
import logging
from tkinter import *
from tkinter import ttk
from dns import resolver, exception as dns_exception
import whois
import threading
from tkinter.scrolledtext import ScrolledText

# Configure logging
logging.basicConfig(filename='asset_monitor.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

hosts_list = []
scanning_thread = None

def load_hosts():
    try:
        with open("hosts.json", "r") as f:
            data = json.load(f)
            for item in data:
                host = Host.from_dict(item)
                hosts_list.append(host)
    except FileNotFoundError:
        pass  # It's okay if the file doesn't exist yet

def save_hosts():
    with open("hosts.json", "w") as f:
        data = [host.to_dict() for host in hosts_list]
        json.dump(data, f)

def display_hosts():
    tree.delete(*tree.get_children())  # Clear the current display
    for host in hosts_list:
        nmap_result = nmap_scan(host)
        unauthorized_ports = [port for port in host.ports if str(port) not in nmap_result]
        status = "red" if unauthorized_ports else "green"
        tree.insert('', 'end', text=f"{host.ipv4}:{','.join(map(str, host.ports))}", tags=(status,))

def start_scanning():
    global scanning_thread
    if scanning_thread is None or not scanning_thread.is_alive():
        scanning_thread = threading.Thread(target=scan_hosts)
        scanning_thread.start()

def scan_hosts():
    for host in hosts_list:
        update_output(f"Scanning host {host.ipv4}")
        nslookup_result = nslookup(host)
        dig_result = dig(host)
        whois_result = whois_lookup(host)
        dns_result = dns_lookup(host)
        nmap_result = nmap_scan(host)

        update_output(f"nslookup result for {host.domain_name}: {nslookup_result}")
        update_output(f"dig result for {host.domain_name}: {dig_result}")
        update_output(f"whois result for {host.domain_name}: {whois_result}")
        update_output(f"DNS lookup result for {host.ipv4}: {dns_result}")
        update_output(f"nmap scan result for {host.ipv4}: {nmap_result}")

        unauthorized_ports = [port for port in host.ports if str(port) not in nmap_result]
        status = "red" if unauthorized_ports else "green"
        tree.item(host.ipv4, tags=(status,))
        root.update()  # Update the GUI to reflect the new status

def update_output(output):
    output_text.config(state='normal')
    output_text.insert(END, output + "\n")
    output_text.config(state='disabled')
    output_text.see(END)

class Host:
    def __init__(self, ipv4=None, domain_name=None, ports=None):
        self.ipv4 = ipv4
        self.domain_name = domain_name
        self.ports = ports if ports is not None else []

    def to_dict(self):
        return {"ipv4": self.ipv4, "domain_name": self.domain_name, "ports": self.ports}

    @classmethod
    def from_dict(cls, data):
        return cls(data.get("ipv4"), data.get("domain_name"), data.get("ports"))

def add_host():
    host_dialog = HostDialog(root)
    host = host_dialog.result
    if host:
        hosts_list.append(host)
        tree.insert('', 'end', text=f"{host.ipv4}:{','.join(map(str, host.ports))}")
        save_hosts()

class HostDialog(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Add Host")

        self.ipv4_label = Label(self, text="IPv4:")
        self.ipv4_entry = Entry(self)
        self.ipv4_label.pack()
        self.ipv4_entry.pack()

        self.domain_label = Label(self, text="Domain Name:")
        self.domain_entry = Entry(self)
        self.domain_label.pack()
        self.domain_entry.pack()

        self.ports_label = Label(self, text="Ports (comma-separated):")
        self.ports_entry = Entry(self)
        self.ports_label.pack()
        self.ports_entry.pack()

        self.add_button = Button(self, text="Add", command=self.add_host)
        self.add_button.pack()

        self.result = None

    def add_host(self):
        ipv4 = self.ipv4_entry.get().strip()
        domain_name = self.domain_entry.get().strip()
        ports = [int(port.strip()) for port in self.ports_entry.get().split(",") if port.strip()]
        if ipv4 and domain_name and ports:
            self.result = Host(ipv4=ipv4, domain_name=domain_name, ports=ports)
            self.destroy()

def sanitize_domain(domain):
    domain = domain.strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("://")[1]
    return domain

def nslookup(host):
    update_output(f"Running nslookup for {host.domain_name}")
    try:
        result = socket.gethostbyname(host.domain_name)
        return result
    except socket.gaierror as e:
        logging.error(f"nslookup failed: {str(e)}")
        return str(e)

def dig(host):
    update_output(f"Running dig for {host.domain_name}")
    dns_resolver = resolver.Resolver()
    try:
        result = str(dns_resolver.resolve(host.domain_name, 'A'))
        return result
    except dns_exception.DNSException as e:
        logging.error(f"Dig failed: {str(e)}")
        return str(e)

def whois_lookup(host):
    update_output(f"Running whois for {host.domain_name}")
    try:
        result = str(whois.whois(host.domain_name))
        return result
    except Exception as e:
        logging.error(f"whois failed: {str(e)}")
        return str(e)

def dns_lookup(host):
    update_output(f"Running DNS lookup for {host.ipv4}")
    try:
        result = str(socket.getfqdn(host.ipv4))
        return result
    except socket.gaierror as e:
        logging.error(f"DNS lookup failed: {str(e)}")
        return str(e)

def nmap_scan(host):
    update_output(f"Running nmap scan for {host.ipv4}")
    command = ['nmap', '-Pn', host.ipv4]
    try:
        result = subprocess.run(command, capture_output=True, text=True).stdout
        return result
    except subprocess.CalledProcessError as e:
        logging.error(f"nmap scan failed: {str(e)}")
        return str(e)

# Implement the main loop
if __name__ == "__main__":
    # Load the list of hosts
    load_hosts()

    # Initialize the GUI
    root = Tk()
    root.title("Asset Monitor")

    output_text = ScrolledText(root, height=10, width=50, state='disabled')
    output_text.pack()

    tree = ttk.Treeview(root)
    tree.pack()

    start_button = Button(root, text="Start Scanning", command=start_scanning)
    start_button.pack()

    add_button = Button(root, text="Add Host", command=add_host)
    add_button.pack()

    display_hosts()

    root.mainloop()
