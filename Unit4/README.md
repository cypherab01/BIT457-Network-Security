### **Unit 4: Wireless Network Security**

-   **Wireless Security**: Addresses risks in wireless networks due to broadcast communication, mobility, and resource constraints.
-   **Mobile Device Security**: Covers threats to smartphones, tablets, and other devices, with strategies to secure them.
-   **IEEE 802.11 Wireless LAN Overview**: Introduces the architecture and terminology of Wi-Fi networks.
-   **IEEE 802.11i Wireless LAN Security**: Details the Robust Security Network (RSN) standard for secure Wi-Fi communication.
-   **Exam Relevance**: Expect questions on wireless threats, mobile security strategies, IEEE 802.11 components, and 802.11i phases/services.

The syllabus lists the following topics for Unit 4:

1. Wireless Security
2. Mobile Device Security
3. IEEE 802.11 Wireless LAN Overview
4. IEEE 802.11i Wireless LAN Security

Let’s begin with **Topic 1: Wireless Security** in detail, following our structured, exam-focused approach.

---

### **Topic 1: Wireless Security**

#### **Definition and Context**

-   **Wireless Security**: The practice of protecting wireless networks and their devices from unauthorized access, eavesdropping, and attacks, ensuring confidentiality, integrity, and availability.
-   **Context**: Wireless networks, such as Wi-Fi, use broadcast communication, making them more vulnerable than wired networks. Security measures address these risks to protect data and services.

#### **Key Factors Increasing Wireless Security Risks**

-   **Channel**:
    -   Wireless networks transmit data via radio waves, enabling eavesdropping or jamming without physical access.
    -   Example: An attacker intercepting Wi-Fi signals in a public café.
-   **Mobility**:
    -   Wireless devices (e.g., laptops, smartphones) are portable, increasing risks of theft, loss, or unauthorized use.
    -   Example: A stolen tablet exposing corporate data.
-   **Resources**:
    -   Devices like smartphones have limited processing power, memory, or battery, constraining security measures (e.g., complex encryption).
    -   Example: A smartwatch unable to run advanced antivirus software.
-   **Accessibility**:
    -   Devices like sensors or IoT gadgets may be unattended in remote/hostile locations, vulnerable to physical tampering.
    -   Example: A weather sensor in a field being hacked.

#### **Wireless Network Threats**

-   **Accidental Association**: Devices unintentionally connect to nearby networks, exposing data.
    -   Example: A laptop connecting to a neighbor’s unsecured Wi-Fi.
-   **Malicious Association**: Attackers create fake access points (APs) to steal credentials.
    -   Example: A rogue AP mimicking a coffee shop’s Wi-Fi to capture passwords.
-   **Ad Hoc Networks**: Peer-to-peer wireless connections without central control, prone to attacks.
    -   Example: Two laptops in ad hoc mode sharing files without authentication.
-   **Nontraditional Networks**: Devices like Bluetooth or PDAs risk eavesdropping or spoofing.
    -   Example: A Bluetooth headset leaking audio data.
-   **Identity Theft (MAC Spoofing)**: Attackers mimic a legitimate device’s MAC address.
    -   Example: Spoofing an authorized MAC to bypass AP restrictions.
-   **Man-in-the-Middle (MITM) Attacks**: Interception and alteration of communications.
    -   Example: Intercepting Wi-Fi traffic to modify banking transactions.
-   **Denial of Service (DoS)**: Overwhelming network resources to disrupt access.
    -   Example: Flooding an AP with requests to disconnect users.
-   **Network Injection**: Injecting malicious packets into unfiltered traffic.
    -   Example: Sending fake routing messages to disrupt network operations.

#### **Wireless Security Measures**

-   **Securing Wireless Transmissions**:
    -   **Signal-Hiding Techniques**: Reduce signal leakage (e.g., directional antennas, lowering transmit power).
    -   **Encryption**: Protect data confidentiality (e.g., WPA3 encryption for Wi-Fi).
    -   Example: Using AES in WPA3 to secure data over a public Wi-Fi network.
-   **Securing Wireless Access Points**:
    -   **IEEE 802.1X**: Port-based authentication to control AP access.
    -   Example: Requiring user credentials before connecting to a corporate AP.
-   **Securing Wireless Networks**:
    -   **Use Encryption**: Implement strong protocols like WPA3.
    -   **Antivirus/Antispyware**: Protect devices from malware.
    -   **Turn Off Identifier Broadcasting**: Hide SSID to reduce visibility.
    -   **Change Default Settings**: Update default AP identifiers and passwords.
    -   **Restrict Access**: Allow only specific devices (e.g., MAC filtering).
    -   Example: Disabling SSID broadcast and using WPA3 on a home Wi-Fi network.

#### **Components Vulnerable to Attacks**

-   **Endpoint**: Devices like laptops or smartphones connecting to the network.
-   **Wireless Medium**: The radio frequency channel used for communication.
-   **Access Point (AP)**: The device bridging wireless and wired networks.
-   **Example**: An unsecured AP allowing attackers to intercept all network traffic.

#### **Importance**

-   **Threat Mitigation**: Addresses wireless-specific vulnerabilities like eavesdropping or rogue APs.
-   **Data Protection**: Ensures confidentiality and integrity of transmitted data.
-   **Network Availability**: Prevents disruptions from DoS or injection attacks.
-   **Compliance**: Aligns with standards requiring secure wireless practices (e.g., PCI-DSS for retail Wi-Fi).

#### **Exam Focus Points**

-   **Risk Factors**: Memorize the four factors (channel, mobility, resources, accessibility) and their implications.
-   **Threats**: Know the eight wireless threats and examples for each.
-   **Security Measures**: Understand transmission, AP, and network-level protections.
-   **Components**: Identify endpoint, wireless medium, and AP as attack points.
-   **Applications**: Link measures to scenarios (e.g., securing public Wi-Fi).

#### **Potential Exam Questions**

1. What is wireless security? Why is it more challenging than wired network security? (Short Answer)
2. List and briefly define four threats to wireless networks. (List)
3. Explain three wireless security measures and their purposes. Provide examples. (Descriptive)
4. What are the key factors increasing wireless security risks? Illustrate with a scenario. (Conceptual)
5. How does IEEE 802.1X enhance wireless access point security? (Short Answer)

---

Let’s continue with your Network Security exam preparation for **Unit 4: Wireless Network Security**. Following our structured, exam-focused approach, we’ll now cover **Topic 2: Mobile Device Security**, as per the syllabus from "BIT 457 - Network Security.pdf". I’ll use the provided "Unit 4.pdf" and references (e.g., Stallings’ _Cryptography and Network Security_) for supplementary information, ensuring alignment with the syllabus. The material will be presented in a clear, detailed, and markdown-formatted manner, emphasizing exam-relevant points, with potential exam questions included. After this topic, I’ll confirm your readiness to move to the next one.

---

### **Topic 2: Mobile Device Security**

#### **Definition and Context**

-   **Mobile Device Security**: The practice of protecting mobile devices (e.g., smartphones, tablets, memory sticks) and their data from unauthorized access, theft, malware, and other threats, ensuring the confidentiality, integrity, and availability of information.
-   **Context**: Mobile devices are integral to organizational networks, offering convenience and productivity but introducing significant security risks due to their portability, connectivity, and widespread use.

#### **Importance**

-   **Network Integration**: Mobile devices connect to corporate networks, making them potential entry points for attacks.
-   **Data Sensitivity**: Store sensitive data (e.g., emails, corporate documents), requiring robust protection.
-   **Regulatory Compliance**: Must comply with standards like GDPR or HIPAA, which mandate secure handling of personal or health data.
-   **User Mobility**: Devices move across trusted and untrusted networks (e.g., public Wi-Fi), increasing exposure to threats.

#### **Security Threats to Mobile Devices**

-   **Lack of Physical Security Controls**:
    -   Devices are easily lost or stolen, exposing data.
    -   Example: A stolen smartphone revealing corporate emails.
-   **Use of Untrusted Mobile Devices**:
    -   Non-compliant or personal devices (BYOD) may lack security configurations.
    -   Example: An employee’s unpatched tablet introducing malware.
-   **Use of Untrusted Networks**:
    -   Connecting to insecure Wi-Fi risks data interception.
    -   Example: Using public Wi-Fi to access sensitive company data.
-   **Use of Applications Created by Unknown Parties**:
    -   Third-party apps may contain malware or exploit vulnerabilities.
    -   Example: A malicious app stealing banking credentials.
-   **Use of Untrusted Content**:
    -   Content like PDFs or links can deliver malware.
    -   Example: Opening a phishing email attachment on a phone.
-   **Interaction with Other Systems**:
    -   Insecure data exchange with peripherals or other devices.
    -   Example: Syncing with a compromised PC via USB.
-   **Use of Location Services**:
    -   Tracking exposes user movements, compromising privacy.
    -   Example: An app sharing location data without consent.

#### **Mobile Device Security Strategy**

Organizations implement a multi-faceted strategy combining device-level, traffic-level, and network-level controls. The notes categorize these as:

1. **Device Security**:

    - **Definition**: Configures devices with security controls to protect against threats and unauthorized access.
    - **Methods**:
        - **Auto-Lock**: Enables screen lock after inactivity.
        - **Password/PIN Protection**: Requires strong credentials for access.
        - **Disable Auto-Complete**: Prevents storing usernames/passwords.
        - **Enable SSL Protection**: Ensures secure communications (e.g., HTTPS).
        - **Remote Wipe**: Erases data if a device is lost/stolen.
        - **Software Updates**: Patches OS and apps to fix vulnerabilities.
        - **Antivirus Software**: Detects and removes malware.
        - **Application Control**: Prohibits unapproved apps or uses sandboxes for isolation.
        - **Data Restrictions**: Prohibits sensitive data storage or encrypts it.
    - **Example**: Configuring corporate smartphones to auto-lock, use MFA, and enable remote wipe.
    - **Purpose**: Secures the device itself, reducing risks from theft or malware.

2. **Traffic Security**:

    - **Definition**: Protects data transmitted between mobile devices and networks.
    - **Methods**:
        - **Encryption**: Uses protocols like SSL/TLS or IPsec for secure data transfer.
        - **Virtual Private Networks (VPNs)**: Routes traffic through encrypted tunnels.
        - **Strong Authentication**: Verifies device and user identity (e.g., two-layer authentication: device + user).
    - **Example**: Requiring a VPN for employees accessing corporate servers from mobile devices.
    - **Purpose**: Ensures confidentiality and integrity of data in transit, especially on untrusted networks.

3. **Barrier Security**:
    - **Definition**: Implements network-level controls to protect against unauthorized access from mobile devices.
    - **Methods**:
        - **Firewall Policies**: Restrict mobile device traffic (e.g., limit app access).
        - **Intrusion Detection/Prevention Systems (IDS/IPS)**: Monitor and block suspicious mobile traffic.
        - **Access Controls**: Enforce policies based on device compliance or user roles.
    - **Example**: A firewall blocking unverified mobile devices from accessing internal servers.
    - **Purpose**: Safeguards the network from compromised or unauthorized devices.

#### **Bring Your Own Device (BYOD) Considerations**

-   **Challenge**: Employees using personal devices for work increase security risks due to varied configurations.
-   **Solution**: Establish BYOD policies with configuration guidelines (e.g., mandatory antivirus, OS updates) and use Mobile Device Management (MDM) tools to enforce compliance.
-   **Example**: Requiring BYOD devices to install an MDM agent for security monitoring.

#### **Importance**

-   **Threat Mitigation**: Addresses risks like data leaks, malware, and unauthorized access.
-   **Network Protection**: Prevents mobile devices from compromising broader network security.
-   **User Productivity**: Balances security with usability to support mobile workforces.
-   **Compliance**: Meets regulatory requirements for data protection on mobile devices.

#### **Exam Focus Points**

-   **Threats**: Memorize the seven mobile device threats and their implications.
-   **Security Strategies**: Understand device, traffic, and barrier security methods with examples.
-   **BYOD**: Know the challenges and solutions for BYOD policies.
-   **Applications**: Link strategies to real-world scenarios (e.g., securing corporate smartphones).
-   **Components**: Focus on how MDM, VPNs, and firewalls integrate into mobile security.

#### **Potential Exam Questions**

1. What is mobile device security? Why is it critical for organizational networks? (Short Answer)
2. List and briefly define four threats to mobile devices. (List)
3. Explain the three categories of mobile device security strategies with one example each. (Descriptive)
4. How do BYOD policies address mobile security challenges? Provide a scenario. (Conceptual)
5. What role does a VPN play in mobile device traffic security? (Short Answer)

---

Let’s continue with your Network Security exam preparation for **Unit 4: Wireless Network Security**. Following our structured, exam-focused approach, we’ll now cover **Topic 3: IEEE 802.11 Wireless LAN Overview**, as per the syllabus from "BIT 457 - Network Security.pdf". I’ll use the provided "Unit 4.pdf" and references (e.g., Stallings’ _Cryptography and Network Security_) for supplementary information, ensuring alignment with the syllabus. The material will be presented in a clear, detailed, and markdown-formatted manner, emphasizing exam-relevant points, with potential exam questions included. After this topic, I’ll confirm your readiness to move to the next one.

---

### **Topic 3: IEEE 802.11 Wireless LAN Overview**

#### **Definition and Context**

-   **IEEE 802.11**: A set of standards developed by the IEEE 802 committee for wireless local area networks (WLANs), commonly known as Wi-Fi, defining protocols for wireless communication in the 2.4 GHz, 5 GHz, and other frequency bands.
-   **Context**: IEEE 802.11 enables wireless connectivity for devices like laptops, smartphones, and IoT gadgets, forming the backbone of modern WLANs in homes, offices, and public spaces.

#### **Key Components and Terminology**

The "Unit 4.pdf" provides key terms for IEEE 802.11, essential for understanding its architecture:

-   **Station (STA)**: Any device with IEEE 802.11-compliant MAC and physical layers (e.g., a laptop or smartphone).
-   **Access Point (AP)**: A device that connects wireless stations to a wired network, acting as a bridge and providing access to the distribution system.
-   **Basic Service Set (BSS)**: A group of stations controlled by a single coordination function, typically centered around an AP (infrastructure BSS) or operating independently (independent BSS, IBSS).
-   **Coordination Function**: The logical function determining when a station can transmit or receive data within a BSS (e.g., Distributed Coordination Function, DCF).
-   **Distribution System (DS)**: A system (e.g., wired Ethernet) that interconnects multiple BSSs to form a larger network.
-   **Extended Service Set (ESS)**: A collection of interconnected BSSs and wired LANs appearing as a single logical LAN to higher layers.
-   **MAC Protocol Data Unit (MPDU)**: The unit of data exchanged between MAC entities, including headers and payload.
-   **MAC Service Data Unit (MSDU)**: The data unit delivered between MAC users, passed to/from higher layers.

#### **IEEE 802.11 Architecture**

-   **Basic Service Set (BSS)**:
    -   **Infrastructure BSS**: Stations communicate via an AP, which relays data to other stations or the DS.
        -   Example: A corporate Wi-Fi network where devices connect through an AP.
    -   **Independent BSS (IBSS)**: Stations communicate directly without an AP (ad hoc mode).
        -   Example: Two laptops sharing files directly via Wi-Fi.
-   **Extended Service Set (ESS)**:
    -   Combines multiple BSSs via a DS, enabling seamless roaming across APs.
    -   Example: A university campus Wi-Fi network allowing students to move between buildings without losing connectivity.
-   **Distribution System (DS)**:
    -   Connects APs, typically via wired Ethernet, to form an ESS.
    -   Example: Ethernet switches linking APs in an office building.
-   **Dynamic Association**: Stations can join/leave BSSs dynamically, turning on/off or moving in/out of range.
    -   Example: A smartphone connecting to a new AP as the user moves to a different floor.

#### **Protocol Architecture**

-   **Physical Layer**:
    -   Handles signal encoding/decoding, bit transmission/reception, and specifies frequency bands (e.g., 2.4 GHz, 5 GHz) and antenna characteristics.
    -   Example: Using OFDM (Orthogonal Frequency-Division Multiplexing) for high-speed data transmission.
-   **Media Access Control (MAC) Layer**:
    -   Manages access to the wireless medium, assembles/disassembles frames, and performs error detection.
    -   Functions:
        -   **Frame Assembly**: Creates MPDUs with address, control, and error-detection fields.
        -   **Address Recognition**: Identifies destination/source addresses.
        -   **Error Detection**: Uses Cyclic Redundancy Check (CRC) in the Frame Check Sequence (FCS).
    -   Example: Adding a MAC header to a data packet before transmission.
-   **Logical Link Control (LLC) Layer**:
    -   Ensures reliable frame delivery, tracking successful transmissions and retransmitting failed ones.
    -   Example: Retransmitting a lost frame detected via CRC errors.

#### **MPDU Frame Format**

-   **MAC Control**: Contains protocol control information (e.g., priority).
-   **Destination MAC Address**: Identifies the recipient station.
-   **Source MAC Address**: Identifies the sending station.
-   **MAC Service Data Unit (MSDU)**: The payload from higher layers.
-   **Frame Check Sequence (FCS)**: CRC for error detection.
-   **Structure**: MAC header (control, addresses), MSDU, MAC trailer (FCS).

#### **The Wi-Fi Alliance**

-   **Role**: An industry consortium (originally WECA, formed 1999) ensuring interoperability of 802.11 products across vendors.
-   **Significance**: Certified the first widely adopted standard, 802.11b, and continues to promote compatibility.
-   **Example**: Wi-Fi Certified devices guaranteeing seamless connectivity.

#### **Importance**

-   **Ubiquitous Connectivity**: IEEE 802.11 is the foundation for Wi-Fi, enabling wireless access in diverse environments.
-   **Scalability**: Supports small ad hoc networks to large enterprise ESSs.
-   **Interoperability**: Standardized protocols ensure device compatibility.
-   **Security Foundation**: Provides the framework for security standards like 802.11i (covered in Topic 4).

#### **Exam Focus Points**

-   **Terminology**: Memorize key terms (STA, AP, BSS, ESS, DS, MPDU, MSDU).
-   **Architecture**: Understand BSS, ESS, and DS roles, with examples.
-   **Protocol Layers**: Know the functions of physical, MAC, and LLC layers.
-   **Frame Format**: Be familiar with MPDU components (header, MSDU, FCS).
-   **Wi-Fi Alliance**: Recognize its role in interoperability.

#### **Potential Exam Questions**

1. What is IEEE 802.11? Define its role in wireless LANs. (Short Answer)
2. List and briefly describe three key components of the IEEE 802.11 architecture. (List)
3. Explain the difference between an infrastructure BSS and an independent BSS. Provide examples. (Comparison)
4. Describe the functions of the MAC layer in IEEE 802.11. (Descriptive)
5. What is the role of the Wi-Fi Alliance in IEEE 802.11 networks? (Short Answer)

---

### **Topic 4: IEEE 802.11i Wireless LAN Security**

#### **Definition and Context**

-   **IEEE 802.11i**: An amendment to the IEEE 802.11 standard, known as the Robust Security Network (RSN), designed to enhance Wi-Fi security by providing robust authentication, encryption, and integrity mechanisms.
-   **Context**: Earlier Wi-Fi security protocols like WEP were weak, prompting 802.11i to address vulnerabilities such as eavesdropping, unauthorized access, and data tampering in wireless LANs.

#### **Need for IEEE 802.11i**

-   **Wired vs. Wireless LANs**:
    -   **Wired LANs**: Require physical connection, providing inherent authentication (connection implies access) and privacy (data reception limited to connected devices).
    -   **Wireless LANs**: Allow any device within radio range to transmit/receive, increasing risks of unauthorized access and interception.
-   **Purpose**: 802.11i overcomes these limitations by introducing strong security services, ensuring wireless networks match wired network security levels.

#### **IEEE 802.11i Services**

The standard defines three core security services to protect wireless communications:

1. **Authentication**:

    - **Definition**: A protocol for mutual authentication between a station (STA) and an authentication server (AS), generating temporary keys for secure communication.
    - **Mechanism**: Uses IEEE 802.1X for port-based access control, often with EAP (Extensible Authentication Protocol) methods like EAP-TLS.
    - **Example**: A laptop authenticating to a corporate Wi-Fi using a username/password via EAP.
    - **Purpose**: Verifies identities, preventing unauthorized network access.

2. **Access Control**:

    - **Definition**: Enforces authentication and manages key exchange, ensuring only authenticated devices access the network.
    - **Mechanism**: 802.1X blocks non-authentication traffic until verification, routing messages and facilitating key distribution.
    - **Example**: An AP denying access to a device until EAP authentication succeeds.
    - **Purpose**: Controls network entry and supports secure key management.

3. **Privacy with Message Integrity**:
    - **Definition**: Encrypts MAC-level data and ensures it remains unaltered using a message integrity code (MIC).
    - **Mechanism**: Uses CCMP (Counter Mode with Cipher Block Chaining Message Authentication Code Protocol) with AES-128 for encryption and integrity.
    - **Example**: Encrypting Wi-Fi traffic to prevent eavesdropping and tampering.
    - **Purpose**: Protects data confidentiality and integrity during transmission.

#### **Security Protocols and Algorithms**

-   **Protocols**:
    -   **802.1X/EAP**: Handles authentication and key management.
    -   **4-Way Handshake**: Distributes pairwise and group keys for encryption.
    -   **CCMP**: Provides encryption and integrity (preferred in 802.11i).
    -   **TKIP (Temporal Key Integrity Protocol)**: A transitional protocol for legacy devices, less secure than CCMP.
-   **Cryptographic Algorithms**:
    -   **AES (Advanced Encryption Standard)**: Used in CCMP for robust encryption.
    -   **MIC**: Ensures data integrity in CCMP.
    -   **HMAC-SHA1**: Used in TKIP for integrity (weaker than CCMP).

#### **IEEE 802.11i Phases of Operation**

The standard operates in five distinct phases to establish and maintain secure communication:

1. **Discovery**:

    - **Process**: The AP advertises its security policy (e.g., 802.11i support, cipher suites) via Beacons and Probe Responses. The STA selects an AP and negotiates cipher suites and authentication mechanisms.
    - **Example**: A smartphone detecting a Wi-Fi network and choosing WPA3 (802.11i-compliant).
    - **Purpose**: Identifies compatible security settings for connection.

2. **Authentication**:

    - **Process**: The STA and AS mutually authenticate using 802.1X/EAP. The AP forwards traffic but doesn’t participate, blocking non-authentication traffic until successful.
    - **Example**: A user entering credentials verified by a RADIUS server via EAP-TLS.
    - **Purpose**: Verifies identities and establishes trust.

3. **Key Generation and Distribution**:

    - **Process**: The AP and STA generate cryptographic keys (e.g., Pairwise Master Key, PMK) and distribute them via the 4-Way Handshake, ensuring secure encryption.
    - **Example**: Generating a session key for encrypting Wi-Fi traffic.
    - **Purpose**: Enables secure data transfer with unique keys.

4. **Protected Data Transfer**:

    - **Process**: Data is encrypted (e.g., using CCMP) between the STA and AP, ensuring confidentiality and integrity. Security is not end-to-end but limited to the wireless link.
    - **Example**: Encrypting a file transfer over Wi-Fi to prevent interception.
    - **Purpose**: Safeguards data during transmission.

5. **Connection Termination**:
    - **Process**: The AP and STA exchange frames to tear down the secure connection, restoring the original state.
    - **Example**: Disconnecting a device from Wi-Fi, clearing session keys.
    - **Purpose**: Ensures clean session closure, preventing key reuse.

#### **Key Differences: TKIP vs. CCMP**

| **Aspect**     | **TKIP**                        | **CCMP**                            |
| -------------- | ------------------------------- | ----------------------------------- |
| **Encryption** | RC4 stream cipher               | AES-128 block cipher                |
| **Integrity**  | Michael MIC (64-bit, weaker)    | CBC-MAC (128-bit, stronger)         |
| **Security**   | Less secure, for legacy support | Highly secure, 802.11i standard     |
| **Use Case**   | Transitional for WEP upgrades   | Preferred for modern Wi-Fi networks |

#### **Importance**

-   **Enhanced Security**: Overcomes WEP’s weaknesses with strong encryption (AES) and authentication (802.1X).
-   **Compliance**: Meets industry standards (e.g., PCI-DSS) for secure wireless networks.
-   **User Trust**: Ensures safe Wi-Fi usage in public, corporate, or home environments.
-   **Interoperability**: Supports modern Wi-Fi devices with robust security protocols.

#### **Exam Focus Points**

-   **Services**: Memorize authentication, access control, and privacy with message integrity.
-   **Phases**: Understand the five phases (Discovery, Authentication, Key Generation, Protected Data Transfer, Connection Termination).
-   **Protocols/Algorithms**: Know 802.1X, CCMP, TKIP, and AES roles.
-   **TKIP vs. CCMP**: Be ready to compare their security and use cases.
-   **Applications**: Link to scenarios like securing corporate Wi-Fi or public hotspots.

#### **Potential Exam Questions**

1. What is IEEE 802.11i? Why was it developed? (Short Answer)
2. List and briefly describe the three security services provided by IEEE 802.11i. (List)
3. Explain the five phases of operation in IEEE 802.11i with examples. (Descriptive)
4. Differentiate between TKIP and CCMP in terms of encryption and security. (Comparison)
5. How does 802.1X contribute to IEEE 802.11i authentication? (Short Answer)
