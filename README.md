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
  

   ![image](https://github.com/oussben811/Network-Scanner/assets/78149349/83254d5e-fbd2-4f7d-a593-1dfca22f6ce6)
    
- Terminal output
  

   ![image](https://github.com/oussben811/Network-Scanner/assets/78149349/f06bddee-35cb-490d-9557-9f2ad7c93b65)

## 2. Example 2: IP Range, Multiple Ports Scan
- Graphical output

   ![image](https://github.com/oussben811/Network-Scanner/assets/78149349/d8ccf96a-635f-4d5f-a10c-182af72179da)

- Terminal output
  
  ![image](https://github.com/oussben811/Network-Scanner/assets/78149349/a46752f8-e11e-49f6-89a1-423aecacc534)

## 4. Example 4: IP Range, Port Range Scan
- Graphical output
  
    ![image](https://github.com/oussben811/Network-Scanner/assets/78149349/26a6a758-02d5-48af-b2ad-fd55be12212f)

-  Terminal output

   ![image](https://github.com/oussben811/Network-Scanner/assets/78149349/eddfce6e-44f1-4872-a5d5-ed23c99ebfc8)


## 5. Example 5: Handling Invalid Inputs

   ![image](https://github.com/oussben811/Network-Scanner/assets/78149349/f19f3516-67c4-489d-bfec-c77fd95d2244)

   ![image](https://github.com/oussben811/Network-Scanner/assets/78149349/9a6698a8-2ded-4d3d-8182-bd7c02fbffd8)


## 6. Example 6: Generating Log File (PDF)

  ![image](https://github.com/oussben811/Network-Scanner/assets/78149349/05a86af4-6a85-4e53-948f-1912c687912f)
  
  ![image](https://github.com/oussben811/Network-Scanner/assets/78149349/9a692cce-c24c-4b38-9347-2e4693aeaa95)


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


# VIII.Conclusion

In conclusion, the Network Scanner project emerges as a pivotal and adaptable solution, catering to the diverse needs of network administrators, security professionals, and technology enthusiasts. With an intuitive interface and robust functionalities, it serves as a vital tool for safeguarding the security and optimizing the efficiency of computer networks.

The project's seamless integration of user-friendly features facilitates accessibility for users at varying levels of expertise. Simultaneously, its advanced capabilities, including thorough network scans, device identification, and security risk assessments, establish it as a comprehensive solution for proactive network management.

The commitment to providing warning messages and generating detailed PDF reports enhances the project's value by offering a thorough understanding of potential vulnerabilities. In an era of constant technological evolution, the Network Scanner's adaptability positions it as a reliable companion, ready to address the ever-changing landscape of network security challenges.

Ultimately, the Network Scanner stands out as an essential asset, empowering users in their ongoing quest for network excellence. Its capacity to evolve with the shifting dynamics of technology underscores its significance as a dependable and forward-looking solution in the realm of network security and management.





