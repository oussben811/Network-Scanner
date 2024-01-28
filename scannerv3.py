import nmap
from scapy.all import ARP, Ether, srp
import tkinter as tk
from tkinter import ttk
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import textwrap
from tkinter import messagebox
import ipaddress


devices_t = []
######################################
def scan_devices(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    result = srp(packet, timeout=3, verbose=0, retry=2)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'risks': [],  'open_ports': {}})
    return devices


def scan_ports(target_ip, port_range):
    scanner = nmap.PortScanner()

    scanner.scan(target_ip, arguments=f"-p {port_range} -sV")

    open_ports = {}
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                if state == 'open':
                    service = scanner[host][proto][port]['name']
                    open_ports[port] = service

    return open_ports, scanner


def check_security_risks(open_ports, scanner):
    security_risks = []

    # Check for common security risks
    insecure_services = {
        '21': 'FTP',
        '22': 'SSH',
        '23': 'Telnet',
        '25': 'SMTP',
        '80': 'HTTP',
        '110': 'POP3',
        '135': 'MS RPC',
        '139': 'NetBIOS',
        '143': 'IMAP',
        '443': 'HTTPS',
        '445': 'Microsoft-DS (SMB)',
        '3306': 'MySQL',
        '3389': 'RDP (Remote Desktop)',
        '5900': 'VNC',
        '5432': 'PostgreSQL',
        '6379': 'Redis',
        '8080': 'HTTP (Alternative)',
        '8443': 'HTTPS (Alternative)',
        '903': 'VMware Server Management Interface',
        '1521': 'Oracle Database',
        '27017': 'MongoDB',
    }

    # Dictionary to map services to warning messages
    warning_messages = {
        'FTP': "FTP is a file transfer protocol. Avoid using FTP unless necessary, as it transmits data in plaintext.",
        'SSH': "SSH is a secure protocol used for remote access. Ensure strong authentication and secure configurations.",
        'Telnet': "Telnet transmits data in plaintext. Avoid using Telnet and consider using SSH for secure remote access.",
        'SMTP': "SMTP is used for email transmission. Ensure proper email security measures to prevent abuse.",
        'HTTP': "HTTP is a protocol used for transmitting data. Having an open HTTP port may expose sensitive information if not properly configured.",
        'POP3': "POP3 is used for email retrieval. Consider using IMAP or secure alternatives instead of POP3.",
        'MS RPC': "MS RPC (Microsoft Remote Procedure Call) is a protocol that can be exploited for attacks. Secure it with appropriate measures.",
        'NetBIOS': "NetBIOS can pose security risks. Disable if not needed, or secure it with appropriate measures.",
        'IMAP': "IMAP is used for email retrieval. Consider using secure alternatives and enable encryption.",
        'HTTPS': "HTTPS is a secure version of HTTP. Ensure proper certificate configuration for secure communication.",
        'Microsoft-DS (SMB)': "SMB is used for file sharing. Secure it to prevent unauthorized access and data exposure.",
        'MySQL': "MySQL is a database service. Secure it with strong authentication and access controls.",
        'RDP (Remote Desktop)': "RDP provides remote desktop access. Secure it with strong passwords and network restrictions.",
        'VNC': "VNC provides remote desktop access. Secure it with strong authentication and encryption.",
        'PostgreSQL': "PostgreSQL is a database service. Secure it with strong authentication and access controls.",
        'Redis': "Redis is an in-memory data structure store. Secure it with authentication and access controls.",
        'HTTP (Alternative)': "An alternative HTTP port. Ensure proper configurations for secure communication.",
        'HTTPS (Alternative)': "An alternative HTTPS port. Ensure proper certificate configuration for secure communication.",
        'VMware Server Management Interface': "VMware Server Management Interface on port 903. Secure it with strong authentication and access controls.",
        'Oracle Database': "Oracle Database service. Secure it with strong authentication and access controls.",
        'MongoDB': "MongoDB is a NoSQL database. Secure it with strong authentication and access controls.",
    }

    for port, service in open_ports.items():
        port_str = str(port)
        if port_str in insecure_services:
            service_name = insecure_services[port_str]
            risk_message = f"{service_name} service on port {port_str} is open (considered insecure)"

            # Add warning message if available for the service
            if service_name in warning_messages:
                risk_message += f": {warning_messages[service_name]}"

            security_risks.append(risk_message)
            print(risk_message)
            # Check for version information

    return security_risks
def scan_network(ip_range, port_range, result_text):
    if not is_valid_ip(ip_range):
        messagebox.showerror("Error", "Invalid IP address. Please enter a valid IP.\n ex 192.168.0.1 or 192.168.0.1/24")
        ip_entry.delete(0, tk.END)
        port_entry.delete(0, tk.END)
        return

    if not is_valid_port(port_range) and port_range!="":
        messagebox.showerror("Error", "Invalid port number. Please enter a valid port.\n ex 80 or 80,135 or 1-1000 ")
        port_entry.delete(0, tk.END)
        return

    global devices_t  # Declare devices_t as a global variable
    devices = scan_devices(ip_range)

    if devices!=[]:
        for device in devices:
            # Display information in the GUI
            result_text.insert(tk.END, f"\nIP: {device['ip']}, MAC: {device['mac']}\n")
            result_text.update_idletasks()

            # Print information to the terminal
            print(f"\nIP: {device['ip']}, MAC: {device['mac']}")

            open_ports, scanner = scan_ports(device['ip'], port_range)
            device['open_ports'] = open_ports  # Add open_ports information to the device dictionary

            # Display information in the GUI
            result_text.insert(tk.END, f"Scanning open ports for device - IP: {device['ip']}, MAC: {device['mac']}\n")
            result_text.insert(tk.END, "Open ports:\n")
            result_text.update_idletasks()

            # Print information to the terminal
            print(f"Scanning open ports for device - IP: {device['ip']}, MAC: {device['mac']}")
            print("Open ports:")

            if open_ports:
                for port in open_ports:
                    # Display information in the GUI
                    result_text.insert(tk.END, f"-  Port: {port}\n")
                    result_text.update_idletasks()

                    # Print information to the terminal
                    print(f"-  Port: {port}")

            else:
                # Display information in the GUI
                result_text.insert(tk.END, "  No open ports found.\n")
                result_text.update_idletasks()

                # Print information to the terminal
                print("  No open ports found.")

            security_risks = check_security_risks(open_ports, scanner)
            if security_risks:
                # Display information in the GUI
                result_text.insert(tk.END, "Security risks:\n")
                result_text.update_idletasks()
                result_text.tag_configure("security_risk_tag", foreground="red")

                # Print information to the terminal
                print("Security risks:")

                for risk in security_risks:
                    # Display information in the GUI
                    result_text.insert(tk.END, f"\n\t+  {risk}\n", "security_risk_tag")
                    result_text.update_idletasks()

                    # Print information to the terminal
                    print(f"\n+  {risk}")

                device['risks'].extend(security_risks)

            else:
                # Display information in the GUI
                result_text.insert(tk.END, "  No security risks found.\n")
                result_text.update_idletasks()

                # Print information to the terminal
                print("No security risks found.")

            # Display information in the GUI
            result_text.insert(tk.END, "--------------------------------------------------\n")
            result_text.update_idletasks()

            # Print information to the terminal
            print("----------------------------------------")
    else:
        result_text.insert(tk.END, "\nNo device found on the network\n")
        result_text.update_idletasks()  # Update the GUI
    devices_t = devices


def generate_pdf(devices):
    pdf_filename = r"C:\Users\oussa\Downloads\network_scan_results.pdf"  # Use the desired path
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    page_number = 1
    c.setStrokeColorRGB(0, 0, 0)  # Set border color to black
    c.rect(30, 30, 550, 750, stroke=1, fill=0)
    c.setFont("Helvetica-Bold", 16)
    title = "Network Scan Results"
    c.drawCentredString(300, 750, title)

    c.setFont("Helvetica", 12)
    c.drawRightString(570, 15, f"Page {page_number}")
    c.drawString(30, 15, "Made by Oussama BENDADA")
    y_position = 750  # Initial y-position

    for device in devices:
        # Check if a new page is needed
        if y_position <= 50:
            c.showPage()
            y_position = 750
            page_number += 1

            # Add borders and footer on each new page
            c.setStrokeColorRGB(0, 0, 0)
            c.rect(30, 30, 550, 750, stroke=1, fill=0)

            c.setFont("Helvetica", 12)
            c.drawRightString(570, 15, f"Page {page_number}")
            c.drawString(30, 15, "Made by Oussama BENDADA")

        y_position -= 20  # Move to a new line for each device
        c.drawString(100, y_position, f"IP: {device['ip']}, MAC: {device['mac']}")

        y_position -= 20  # Move to a new line for open ports
        c.drawString(100, y_position, "Open ports:")
        open_ports = device.get('open_ports', {})
        if open_ports:
            for port in open_ports:
                y_position -= 20  # Move to a new line for each open port
                c.drawString(120, y_position, f"  Port: {port}")
        else:
            y_position -= 20  # Move to a new line for "No ports found"
            c.drawString(120, y_position, "  No ports found")

        y_position -= 20  # Move to a new line for security risks
        c.drawString(100, y_position, "Security risks:")
        security_risks = device.get('risks', [])
        if security_risks:
            for risk in security_risks:
                # Wrap the text into smaller chunks for proper display
                wrapped_lines = textwrap.wrap(risk, width=60)
                for line in wrapped_lines:
                    y_position -= 20  # Move to a new line for each line of text
                    c.drawString(120, y_position, line)
        else:
            y_position -= 20  # Move to a new line for "No security risks found"
            c.drawString(120, y_position, "  No security risks found")

        y_position -= 20  # Move to a new line for the separator
        c.drawString(100, y_position, "---------------------------------------------------------")

    c.save()
    print(f"PDF report saved to {pdf_filename}")
    messagebox.showinfo("PDF Generation", f"PDF report saved to {pdf_filename}")

def is_valid_ip(ip):
    try:
        # Check if the input is a valid IP address or IP network
        ipaddress.IPv4Network(ip, strict=False)
        return True
    except ValueError:
        return False

def is_valid_port(port):
    try:
        # Check if the input is a comma-separated list of ports
        if "," in port:
            ports = [int(p) for p in port.split(",")]
            return all(0 <= p <= 65535 for p in ports)
        # Check if the input is a valid port range (e.g., "1-1000")
        elif "-" in port:
            start, end = map(int, port.split("-"))
            return 0 <= start <= end <= 65535
        else:
            # Check if the input is a valid single port
            port_num = int(port)
            return 0 <= port_num <= 65535
    except ValueError:
        return False

def refresh():
    ip_entry.delete(0, tk.END)
    port_entry.delete(0, tk.END)
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)

def start_scan():
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)

    ip_range = ip_entry.get()
    port_range = port_entry.get()

    result_text.delete(1.0, tk.END)  # Clear previous results
    scan_network(ip_range, port_range, result_text)
    result_text.config(state=tk.DISABLED)

root = tk.Tk()
root.title("Network Scanner",)

root.configure(bg="lightblue")

style = ttk.Style()
style.configure("TFrame", background="lightblue")

input_frame = ttk.Frame(root, padding="10", style="TFrame")
input_frame.grid(row=0, column=0, sticky="ns")

frame_width = input_frame.winfo_screenwidth() // 5

labels_frame = ttk.Frame(input_frame, style="TFrame")
labels_frame.grid(row=0, column=0, pady=5, padx=5, sticky="w")

buttons_frame = ttk.Frame(input_frame, style="TFrame")
buttons_frame.grid(row=0, column=1, pady=5, padx=5, sticky="e")

result_frame = ttk.Frame(root, padding="10", style="TFrame")
result_frame.grid(row=1, column=0, sticky="ns")

style = ttk.Style()
style.configure("TLabel", font=("Arial", 12), foreground="black", background="lightblue")
style.configure("TEntry", font=("Arial", 12), fieldbackground="lightblue")
style.configure("TButton", font=("Arial", 12, "bold"), foreground="blue", background="lightblue")
style.configure("RefreshButton.TButton", font=("Arial", 12, "bold"), foreground="black", background="grey")

ip_label = ttk.Label(labels_frame, text="IP Range:")
ip_label.grid(row=0, column=0, pady=5, padx=5, sticky="w")

ip_entry = ttk.Entry(labels_frame, width=27)
ip_entry.grid(row=0, column=1, pady=5, padx=5, sticky="e")

port_label = ttk.Label(labels_frame, text="Port Range:")
port_label.grid(row=1, column=0, pady=5, padx=5, sticky="w")

port_entry = ttk.Entry(labels_frame, width=27)
port_entry.grid(row=1, column=1, pady=5, padx=5, sticky="e")

scan_button = ttk.Button(buttons_frame, text="Scan Network", command=start_scan, width=15)
scan_button.grid(row=0, column=0, pady=5, padx=5)

icon_image = tk.PhotoImage(file='refresh.png')
refresh_button = ttk.Button(buttons_frame, command=refresh, width=8, style="RefreshButton.TButton", image=icon_image)
refresh_button.grid(row=2, column=0, pady=5, padx=5)

generate_pdf_button = ttk.Button(buttons_frame, text="Generate Logs", command=lambda: generate_pdf(devices_t), width=15)
generate_pdf_button.grid(row=1, column=0, pady=5, padx=5)

input_frame.columnconfigure(0, weight=1, minsize=frame_width)
input_frame.columnconfigure(1, weight=1, minsize=frame_width)

result_text = tk.Text(result_frame, wrap=tk.WORD, height=20, width=80)
result_text.pack()

# Start the Tkinter event loop
root.mainloop()
