# I.Introduction:
In the current era of advanced connectivity, where digital ecosystems are intricately woven, the 
demand for robust network solutions is more pressing than ever. The Network Scanner project 
responds to this demand by providing a sophisticated set of tools that empower users to delve 
into the intricate fabric of computer networks. Whether it be for the meticulous analysis of 
network components, the strategic identification of vulnerabilities, or the proactive fortification 
of security protocols, this project offers a comprehensive suite of features.

The Network Scanner project is a Python-based application that provides advanced 
functionalities for network exploration and identification of connected devices. This solution 
aims to offer network administrators and security professionals a powerful and user-friendly 
tool for analyzing networks, detecting devices, and assessing potential risks.

# II.Key Objectives:

- **Device Discovery:** The project employs ARP queries using the Scapy library to detect active 
devices within a specified IP address range. This functionality enables users to have a realtime overview of the devices connected to their network.

- **Port Scanning:** Leveraging the capabilities of Nmap, the Network Scanner explores open 
ports on discovered devices, offering insights into the services running on each device. This 
facilitates a thorough understanding of the network's service landscape.

- **Risk Assessment:** The application goes beyond mere device and port detection by assessing 
potential security risks associated with open ports. It identifies services that might pose 
security threats, providing users with actionable insights to bolster network security.

- **User-Friendly Interface:** Recognizing the importance of accessibility, the project 
incorporates a graphical user interface (GUI) built with Tkinter. This allows users to interact 
seamlessly with the application, specifying parameters for scans and visualizing results in 
an intuitive manner.

- **Report Generation:** A crucial aspect of network management is documentation. The 
project addresses this by integrating ReportLab, enabling the creation of structured PDF 
reports. These reports encapsulate analysis results, facilitating comprehensive 
documentation and post-analysis.

# III.Technological Foundation:

The Network Scanner project strategically harnesses the capabilities of several key 
technologies to deliver a seamless user experience and robust functionalities:

## 1. Nmap:
    Nmap, short for "Network Mapper," is a renowned open-source tool that excels in network 
    exploration and security auditing. Originally developed by Gordon Lyon, Nmap has evolved 
    into a versatile and powerful utility used for discovering devices and services on a computer 
    network. Its robust features include port scanning, version detection, and scriptable 
    interaction with target systems. Nmap's versatility makes it a fundamental component in 
    network security assessments, allowing users to identify potential vulnerabilities and 
    strengthen the overall security posture.
  
## 2. Scapy:
    Scapy is a powerful Python library designed for crafting, sending, and receiving network 
    packets. Developed by Philippe Biondi, Scapy provides a flexible and efficient framework 
    for building custom network tools and applications. Its capabilities extend to network 
    discovery, packet manipulation, and protocol analysis. In the context of the Network 
    Scanner project, Scapy plays a crucial role in the device detection process, particularly 
    through the crafting and sending of ARP (Address Resolution Protocol) queries. This 
    enables the identification of active devices within a given IP range.

## 3. Tkinter:
    Tkinter stands as the standard GUI (Graphical User Interface) library for Python, offering 
    developers a simple yet effective toolkit for creating interactive desktop applications. 
    Tkinter is a part of the standard Python distribution, making it easily accessible for 
    developers looking to build user-friendly interfaces. In the Network Scanner project, Tkinter 
    is utilized to design and implement the graphical interface, allowing users to input scan 
    parameters and receive real-time scan results in an intuitive manner.

## 4. ReportLab:
    ReportLab is a Python library specifically designed for the generation of dynamic PDF 
    documents. With ReportLab, developers can create detailed and structured reports, making 
    it an excellent choice for projects that require document generation capabilities. In the 
    context of the Network Scanner project, ReportLab enhances utility by enabling the creation 
    of informative PDF reports summarizing the scan results. This feature contributes to the 
    project's overall functionality and provides users with a convenient way to document and 
    share network scan findings.

These foundational technologies collectively contribute to the success of the Network Scanner 
project, providing it with the necessary tools to perform comprehensive network scans, present 
results through a user-friendly interface, and generate detailed reports for further analysis and 
documentation.

# IV.Practical Applications in the Real World

The Network Scanner project caters to a diverse set of real-world applications, ensuring its 
relevance and effectiveness in various scenarios:

- **Network Security:** By identifying and mitigating potential vulnerabilities, the project 
significantly contributes to enhancing overall network security.

- **Device Management:** Network administrators can efficiently manage and monitor 
connected devices, streamlining network operations.

- **Security Audits:** Conducting regular security audits becomes a seamless process, 
ensuring network robustness and compliance with security best practices.

- **Documentation Excellence:** The ability to generate detailed reports fosters transparency, 
accountability, and effective communication within network management teams.

# V.Application Overview

Network scanner is an application with a Tkinter-based graphical user interface. It utilizes the 
scapy and nmap libraries for network scanning, and reportlab for PDF report generation. The 
code scans for devices, checks open ports, identifies security risks, and generates a detailed 
PDF report. The Tkinter GUI allows users to input IP and port ranges, initiate scans, and view 
results. Global variables store scan data for generating PDF reports. The code emphasizes 
security by flagging insecure services and providing warnings.

The network scanning functions use ARP requests (scapy) and nmap to discover devices and 
open ports. For instance, it identifies open ports associated with common services like HTTP 
(port 80) and SSH (port 22). Security risks are flagged for insecure services, e.g., FTP (port 
21) transmitting data in plaintext. Warning messages guide users on securing their network, 
e.g., strong authentication for SSH.

The code includes explicit identification of security risks, associating specific services with 
warning messages. It generates a PDF report summarizing device information, open ports, 
and security risks. This report aids administrators in understanding the network's security 
status. In summary, the code integrates network scanning, security risk identification, and 
PDF report generation through a user-friendly Tkinter GUI

## 1. Example 1: Single IP, Multiple Ports Scan
- Graphical output
  
    <img width="448" alt="image" src="https://github.com/oussben811/Network-Scanner/assets/78149349/bfa66e07-c131-4c5e-9f20-dc9eb6ff1ec3">
    
- Terminal output
  
  <img width="448" alt="image" src="https://github.com/oussben811/Network-Scanner/assets/78149349/bb116ca3-3e65-468f-a019-dfb4f1e1cead">

## 2. Example 2: IP Range, Multiple Ports Scan
- Graphical output

  <img width="446" alt="image" src="https://github.com/oussben811/Network-Scanner/assets/78149349/249c28e6-d101-409d-af78-70ea17897eb8">

- Terminal output
  
  <img width="451" alt="image" src="https://github.com/oussben811/Network-Scanner/assets/78149349/004350fb-73d3-4206-bd0e-02dcdb586041">

## 4. Example 4: IP Range, Port Range Scan
- Graphical output

-  Terminal output

## 5. Example 5: Handling Invalid Inputs

## 6. Example 6: Generating Log File (PDF)

# VII.Improving the Network Scanner Project

## 1. Advanced Scanning Techniques:
- **Current State:** The project currently focuses on basic network scanning using Nmap 
and ARP scans.
- **Enhancement:** Incorporate advanced scanning techniques like vulnerability scanning 
and intrusion detection. This involves integrating tools or developing modules that can 
identify and report vulnerabilities in scanned systems.

## 2. User Customization:
- **Current State:** The project has a predefined scanning process with limited user input 
options.
- **Enhancement:** Allow users to define custom scanning profiles based on their specific 
needs. This could include specifying scan intensity, selecting target services, and 
defining exclusion criteria.

## 3. Real-time Collaboration:
- **Current State:** The project provides scan results after the completion of scans.
- **Enhancement:** Introduce real-time collaboration features, enabling multiple users to 
view ongoing scans, share insights, and collectively respond to emerging threats. This 
could involve integrating messaging or collaborative platforms.

## 4. SIEM System Integration:
- **Current State:** The project focuses on standalone scanning without integration into 
larger security ecosystems.
- **Enhancement:** Explore integration with Security Information and Event Management 
(SIEM) systems. This involves formatting and forwarding scan logs to a SIEM for 
centralized monitoring and analysis.

## 5. Enhanced Reporting:
- **Current State:** Project generates basic text-based reports.
- **Enhancement:** Implement more sophisticated reporting features, including data 
visualizations, charts, and graphs for a comprehensive understanding of scan results. 
Additionally, allow users to export reports in multiple formats like PDF or CSV.




