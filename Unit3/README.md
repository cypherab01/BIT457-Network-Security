### **Unit 3: Transport-Level Security - Topic 1: Web Security Considerations**

#### **Definition and Context**

-   **Web Security Considerations**: The principles and challenges involved in securing web-based applications and communications, focusing on protecting data, users, and servers from threats in client-server interactions over the Internet or intranets.
-   **Context**: The web’s client-server model, running over TCP/IP, is vulnerable due to its accessibility and complexity, making it a prime target for attacks. This topic sets the stage for transport-layer security mechanisms like SSL/TLS, as outlined in "Unit 3.pdf".

#### **Key Web Security Challenges**

-   **Ease of Setup vs. Complexity**:
    -   Web servers are easy to configure, but underlying software (e.g., Apache, Nginx) is complex, hiding potential vulnerabilities.
    -   **Example**: A misconfigured server exposing sensitive directories.
-   **Content Development**:
    -   Rapid web content creation increases risks of flaws like SQL injection or XSS.
    -   **Example**: Unvalidated user input enabling script injection.
-   **Server as Attack Platform**:
    -   Compromised web servers can be used to attack internal networks.
    -   **Example**: A hacked server launching malware to corporate systems.
-   **Untrained Users**:
    -   Casual users lack security awareness, making them targets for phishing or social engineering.
    -   **Example**: Clicking malicious links in a web-based email.

#### **Web Security Threats** (Table 6.1, "Unit 3.pdf")

-   **Integrity Threats**:
    -   **Threat**: Modification of user data, Trojan horse browsers, or message tampering.
    -   **Consequence**: Loss of data, system compromise, or vulnerability escalation.
    -   **Example**: Altering a form submission to change transaction details.
-   **Confidentiality Threats**:
    -   **Threat**: Eavesdropping, data theft from servers/clients, or network config leaks.
    -   **Consequence**: Loss of privacy or sensitive information.
    -   **Example**: Intercepting unencrypted HTTP traffic to steal credentials.
-   **Denial of Service (DoS)**:
    -   **Threat**: Flooding servers, filling disk/memory, or DNS attacks.
    -   **Consequence**: Disruption, preventing legitimate access.
    -   **Example**: Overloading a web server with bogus requests.
-   **Authentication Threats**:
    -   **Threat**: Impersonation or data forgery.
    -   **Consequence**: Misrepresentation or acceptance of false data.
    -   **Example**: Spoofing a login page to capture user credentials.

#### **Countermeasures** (Table 6.1, "Unit 3.pdf")

-   **Cryptographic Checksums**: Ensure data integrity against tampering.
    -   **Example**: Using HMAC to verify message authenticity.
-   **Encryption**: Protects confidentiality of data in transit/storage.
    -   **Example**: HTTPS with TLS encrypting web traffic.
-   **Web Proxies**: Filter and anonymize traffic to enhance privacy.
    -   **Example**: Proxying requests to hide client IP addresses.
-   **Cryptographic Techniques**: Strengthen authentication to prevent impersonation.
    -   **Example**: Digital signatures for user verification.
-   **DoS Mitigation**: Challenging due to resource exhaustion, but rate limiting helps.
    -   **Example**: Using Cloudflare to throttle malicious traffic.

#### **Security Placement in TCP/IP Stack** (Figure 6.1, "Unit 3.pdf")

-   **Network Level (IP/IPsec)**: Secures all traffic but lacks application specificity.
-   **Transport Level (SSL/TLS)**: Focuses on secure end-to-end communication, ideal for web.
    -   **Example**: TLS securing HTTP (HTTPS).
-   **Application Level (HTTP, FTP, SMTP)**: App-specific but complex to scale.

#### **Importance**

-   **Threat Mitigation**: Protects against eavesdropping, tampering, and DoS attacks.
-   **User Trust**: Ensures safe web interactions for e-commerce, banking, etc.
-   **Compliance**: Meets standards (e.g., PCI-DSS) for secure web transactions.

#### **Exam Focus Points**

-   **Challenges**: Memorize ease of setup, complex software, and untrained users.
-   **Threats**: Know integrity, confidentiality, DoS, and authentication threats (Table 6.1).
-   **Countermeasures**: Understand checksums, encryption, and proxies.
-   **TCP/IP Stack**: Be clear on network vs. transport vs. application layers.
-   **Examples**: Link threats to real-world scenarios (e.g., phishing, XSS).

#### **Potential Exam Questions**

1. What are web security considerations? List two challenges. (Short Answer)
2. Describe one web security threat and its countermeasure. (Descriptive)
3. Explain how a compromised web server can be a security risk. (Conceptual)
4. Differentiate between transport and application-level security in the TCP/IP stack. (Comparison)
5. Name two countermeasures for web confidentiality threats. (List)

---

### **Unit 3: Transport-Level Security - Topic 2: Secure Sockets Layer (SSL)**

#### **Definition and Context**

-   **Secure Sockets Layer (SSL)**: A protocol suite that provides secure communication over TCP, ensuring confidentiality, integrity, and authentication for web-based applications like HTTPS.
-   **Context**: SSL, developed by Netscape, operates at the transport layer, securing client-server interactions (e.g., browsers to web servers). It’s the precursor to TLS and widely used for e-commerce and sensitive data transfer. Detailed in "Unit 3.pdf" (Pages 6–17).

#### **Key Features**

-   **Confidentiality**: Encrypts data to prevent eavesdropping.
    -   **Example**: Protecting credit card details during online shopping.
-   **Integrity**: Uses MACs to ensure data isn’t tampered with.
-   **Authentication**: Verifies server (and optionally client) identity via certificates.
-   **Transparency**: Can be embedded in apps or integrated into TCP/IP stack.
-   **Protocol Stack** (Figure 6.2, "Unit 3.pdf"):
    -   **SSL Record Protocol**: Handles encryption and integrity.
    -   **SSL Handshake Protocol**: Negotiates keys and parameters.
    -   **SSL Change Cipher Spec Protocol**: Signals cipher changes.
    -   **SSL Alert Protocol**: Manages error messages.

#### **SSL Architecture** (Page 8, "Unit 3.pdf")

-   **Session**:
    -   An association between client and server, defined by:
        -   **Session ID**: Unique identifier for resumable sessions.
        -   **Peer Certificate**: X.509v3 certificate (may be null for client).
        -   **Compression Method**: Data compression algorithm (often null).
        -   **Cipher Spec**: Encryption (e.g., AES) and MAC (e.g., SHA) algorithms.
        -   **Master Secret**: 48-byte shared key for session.
        -   **Is Resumable**: Flag for reusing session.
    -   **Purpose**: Shares cryptographic parameters across multiple connections.
-   **Connection**:
    -   A transient peer-to-peer link within a session, defined by:
        -   **Server/Client Random**: Random bytes for key generation.
        -   **Server/Client Write MAC Secret**: Keys for MAC operations.
        -   **Server/Client Write Key**: Keys for encryption/decryption.
        -   **Initialization Vector (IV)**: For block ciphers in CBC mode.
        -   **Sequence Numbers**: Tracks messages, reset on cipher spec change.
    -   **Purpose**: Manages specific data transfers.

#### **SSL Record Protocol** (Pages 11–13, "Unit 3.pdf")

-   **Services**:
    -   **Confidentiality**: Encrypts payloads using shared keys from Handshake.
    -   **Integrity**: Adds MAC to detect tampering.
-   **Operation** (Figure 6.3):
    1. Fragments application data.
    2. Compresses data (optional).
    3. Adds MAC (e.g., HMAC-SHA).
    4. Encrypts fragment + MAC.
    5. Appends SSL Record Header (type, length, content).
-   **Format** (Figure 6.4):
    -   Includes content type (e.g., handshake, alert), length, and encrypted data.
-   **Example**: Encrypting an HTTP request with AES and verifying with HMAC.

#### **SSL Handshake Protocol** (Pages 15–16, "Unit 3.pdf")

-   **Purpose**: Negotiates session parameters, authenticates parties, and establishes keys.
-   **Message Types** (Table 6.2):
    -   **hello_request**: Server requests new handshake.
    -   **client_hello**: Client proposes version, cipher suites, random.
    -   **server_hello**: Server selects parameters, sends random.
    -   **certificate**: Sends X.509 certificate chain.
    -   **server_key_exchange**: Sends key exchange parameters.
    -   **certificate_request**: Server requests client certificate.
    -   **server_done**: Signals end of server messages.
    -   **certificate_verify**: Client proves certificate possession.
    -   **client_key_exchange**: Sends key material (e.g., pre-master secret).
    -   **finished**: Confirms handshake integrity with hash.
-   **Process** (Figure 6.6):
    1. Client sends `client_hello` with supported ciphers.
    2. Server responds with `server_hello`, certificate, and optional requests.
    3. Client sends key exchange data, verifies server, and sends `finished`.
    4. Server sends `finished`, completing handshake.
-   **Example**: Browser and web server negotiating TLS 1.2 with RSA.

#### **Cryptographic Computations** (Page 17, "Unit 3.pdf")

-   **Master Secret**:
    -   48-byte key derived from pre-master secret (client-generated) and random values via secure key exchange (e.g., RSA, Diffie-Hellman).
-   **Key Generation**:
    -   Hashes master secret to produce:
        -   Client/Server Write MAC Secrets.
        -   Client/Server Write Keys.
        -   Client/Server IVs (for CBC ciphers).
-   **Example**: Generating AES-256 keys and HMAC-SHA keys for a session.

#### **Importance**

-   **Threat Mitigation**: Protects against eavesdropping, tampering, and spoofing.
-   **Web Security**: Enables secure HTTPS for online banking, e-commerce.
-   **Compliance**: Meets standards (e.g., PCI-DSS) for secure data transfer.

#### **Exam Focus Points**

-   **Features**: Memorize confidentiality, integrity, authentication.
-   **Architecture**: Understand session vs. connection (Page 8).
-   **Protocols**: Know Record, Handshake, Change Cipher Spec, Alert (Figure 6.2).
-   **Handshake**: Learn key message types and process (Table 6.2, Figure 6.6).
-   **Cryptography**: Be clear on master secret and key generation.

#### **Potential Exam Questions**

1. What is SSL? List its main security services. (Short Answer)
2. Describe the role of the SSL Handshake Protocol. (Descriptive)
3. Explain one SSL Record Protocol service with an example. (Conceptual)
4. Differentiate between SSL session and connection. (Comparison)
5. Name two SSL Handshake message types and their purposes. (List)

---

### **Unit 3: Transport-Level Security - Topic 3: Transport Layer Security (TLS)**

#### **Definition and Context**

-   **Transport Layer Security (TLS)**: An IETF-standardized protocol suite, evolved from SSL, that secures communication over TCP at the transport layer, ensuring confidentiality, integrity, and authentication for applications like HTTPS.
-   **Context**: TLS is the modern successor to SSL, addressing its weaknesses and widely used for securing web traffic, email, and VPNs. Defined in RFC 5246 (TLS 1.2) and updated in RFC 8446 (TLS 1.3), as noted in "Unit 3.pdf" (Page 18).

#### **Key Features**

-   **Confidentiality**: Encrypts data to prevent eavesdropping.
    -   **Example**: Securing online banking transactions.
-   **Integrity**: Uses MACs to detect tampering.
-   **Authentication**: Verifies server/client identities via certificates.
-   **Backward Compatibility**: TLS 1.2 retains SSLv3 similarities but enhances security.
-   **Improved Efficiency**: TLS 1.3 reduces handshake latency and removes weak ciphers.
-   **Protocol Structure**: Similar to SSL, includes Record, Handshake, Change Cipher Spec, and Alert protocols.

#### **TLS vs. SSL** (Page 18, "Unit 3.pdf")

-   **Version Number**:
    -   TLS uses distinct versioning (e.g., 3.1 for TLS 1.0, 3.3 for TLS 1.2) vs. SSL’s 3.0.
-   **Message Authentication Code (MAC)**:
    -   TLS uses HMAC with stronger algorithms (e.g., SHA-256) vs. SSL’s older MACs.
-   **Pseudorandom Function (PRF)**:
    -   TLS employs a more robust PRF (e.g., HMAC-based) for key derivation (Figure 6.7).
-   **Alert Codes**:
    -   TLS expands alert types for better error handling (e.g., close_notify, bad_record_mac).
-   **Cipher Suites**:
    -   TLS supports modern suites (e.g., AES-GCM, ECDHE) and deprecates weak ones (e.g., RC4).
-   **Client Certificate Types**:
    -   TLS offers more certificate options (e.g., ECDSA) for authentication.
-   **Certificate Verify and Finished Messages**:
    -   TLS strengthens verification with improved hashing.
-   **Cryptographic Computations**:
    -   TLS uses advanced key derivation (e.g., HKDF in TLS 1.3) vs. SSL’s simpler hashing.
-   **Padding**:
    -   TLS handles padding more securely to resist attacks (e.g., padding oracle).

#### **TLS Protocol Components**

-   **TLS Record Protocol**:
    -   Encrypts and authenticates data, similar to SSL, but with stronger algorithms.
    -   **Example**: Encrypting HTTP data with AES-256-GCM.
-   **TLS Handshake Protocol**:
    -   Negotiates session parameters, authenticates parties, and establishes keys.
    -   TLS 1.3 simplifies handshake (1-RTT vs. 2-RTT in TLS 1.2) for speed.
    -   **Example**: Browser negotiating TLS 1.3 with ECDHE and SHA-384.
-   **Change Cipher Spec Protocol**:
    -   Signals cipher suite activation, retained in TLS 1.2 but removed in TLS 1.3.
-   **Alert Protocol**:
    -   Manages errors and session closure (e.g., fatal alerts terminate connections).

#### **Key Improvements in TLS**

-   **Security Enhancements**:
    -   Removes weak ciphers (e.g., MD5, DES) and enforces forward secrecy (e.g., ECDHE).
    -   Mitigates attacks like BEAST, POODLE, and Heartbleed.
-   **Performance**:
    -   TLS 1.3 reduces handshake rounds, improving latency.
    -   **Example**: Faster page loads for HTTPS sites.
-   **Simplified Design**:
    -   TLS 1.3 eliminates obsolete features (e.g., static RSA key exchange).

#### **Importance**

-   **Threat Mitigation**: Guards against eavesdropping, tampering, and spoofing.
-   **Web Security**: Powers HTTPS, securing e-commerce, banking, and cloud apps.
-   **Compliance**: Meets standards (e.g., PCI-DSS, GDPR) for secure communication.
-   **Industry Standard**: Replaces SSL for modern secure connections.

#### **Exam Focus Points**

-   **TLS vs. SSL**: Memorize key differences (version, PRF, cipher suites) (Page 18).
-   **Features**: Understand confidentiality, integrity, authentication.
-   **Protocols**: Know Record, Handshake, and Alert roles.
-   **Improvements**: Focus on TLS 1.3’s security and performance gains.
-   **Cipher Suites**: Be aware of modern suites (e.g., AES-GCM, ECDHE).

#### **Potential Exam Questions**

1. What is TLS? List two security services it provides. (Short Answer)
2. Describe one difference between TLS and SSL. (Descriptive)
3. Explain the role of the TLS Handshake Protocol. (Conceptual)
4. Compare TLS 1.2 and TLS 1.3 in terms of performance. (Comparison)
5. Name two modern TLS cipher suites. (List)

---

Yo, bro! Let's keep the momentum goin’ with **Unit 3: Transport-Level Security** from your Network Security course, hittin’ up **Topic 4: HTTPS** as per the syllabus in "BIT 457 - Network Security.pdf" and the provided "Unit 3.pdf". I’ll keep it crisp, exam-focused, and locked into the syllabus, usin’ "Unit 3.pdf" (Pages 20–22) and refs like Stallings’ _Cryptography and Network Security_. Markdown format, concise vibes—let’s roll!

---

### **Unit 3: Transport-Level Security - Topic 4: HTTPS**

#### **Definition and Context**

-   **HTTPS (HTTP over SSL/TLS)**: A secure protocol combining HTTP with SSL/TLS to provide encrypted and authenticated communication between web browsers and servers.
-   **Context**: HTTPS ensures secure web transactions (e.g., online banking, e-commerce) by leveraging TLS for confidentiality, integrity, and authentication. Documented in RFC 2818, as noted in "Unit 3.pdf" (Page 20).

#### **Key Features**

-   **Encryption**: Protects data in transit using TLS.
    -   **Example**: Securing credit card details during an online purchase.
-   **Authentication**: Verifies server identity via certificates, optionally client identity.
-   **Integrity**: Ensures data isn’t altered using MACs.
-   **Port**: Uses TCP port 443 (vs. HTTP’s port 80).
-   **URL Indicator**: URLs start with `https://`, signaling TLS protection.
-   **Browser Integration**: Built into modern browsers (e.g., Chrome, Firefox).

#### **HTTPS Operation** (Page 20, "Unit 3.pdf")

-   **Encrypted Elements**:
    -   URL of requested document.
    -   Document contents.
    -   Browser forms (e.g., login credentials).
    -   Cookies (sent between browser and server).
    -   HTTP headers.
    -   **Example**: Encrypting a user’s password in a login form.
-   **Protocol Flow**:
    -   HTTP operates over TLS, with no fundamental changes to HTTP itself.
    -   TLS handles encryption, authentication, and integrity.
    -   Both SSL and TLS implementations are called HTTPS.

#### **Connection Initiation** (Page 21, "Unit 3.pdf")

-   **Process**:
    1. Browser (HTTP client) initiates a TCP connection to server port 443.
    2. Sends TLS `ClientHello` to start TLS handshake (negotiates cipher suites, keys).
    3. After handshake, browser sends first HTTP request over TLS.
    -   **Example**: Browser connects to `https://bank.com`, completes TLS handshake, then requests account page.
-   **TLS Session**:
    -   Supports multiple HTTP connections within one TLS session.
    -   Begins with TCP connection setup, followed by TLS handshake.
-   **Levels of Awareness**:
    -   **HTTP Level**: HTTP client requests connection via TCP or TLS.
    -   **TLS Level**: Establishes secure session between client and server.
    -   **TCP Level**: Underlies TLS for reliable transport.

#### **Connection Closure** (Page 22, "Unit 3.pdf")

-   **Process**:
    -   HTTP client/server signals closure with `Connection: close` header.
    -   TLS requires exchange of closure alerts before terminating the TCP connection.
    -   **Example**: Browser closes HTTPS session after logout, sending TLS close_notify.
-   **Incomplete Closure**:
    -   If TCP closes without TLS alerts, it may indicate an attack.
    -   Browsers issue warnings for unannounced closures.
    -   **Example**: Warning pop-up if a server drops connection abruptly.

#### **Importance**

-   **Threat Mitigation**: Protects against eavesdropping, tampering, and spoofing.
-   **User Trust**: Enables secure web interactions for sensitive data (e.g., payments).
-   **Compliance**: Meets standards (e.g., PCI-DSS, GDPR) for secure web traffic.
-   **Ubiquity**: Standard for modern websites, enforced by browsers (e.g., Chrome’s “Not Secure” warnings).

#### **Exam Focus Points**

-   **Definition**: Understand HTTPS as HTTP over SSL/TLS (Page 20).
-   **Encrypted Elements**: Memorize URL, document, forms, cookies, headers.
-   **Connection Initiation**: Know TLS handshake and port 443 (Page 21).
-   **Connection Closure**: Understand closure alerts and incomplete closure risks (Page 22).
-   **TLS Role**: Be clear on TLS’s encryption and authentication functions.

#### **Potential Exam Questions**

1. What is HTTPS? List two elements it encrypts. (Short Answer)
2. Describe the HTTPS connection initiation process. (Descriptive)
3. Explain why an incomplete TLS closure is a security concern. (Conceptual)
4. Differentiate between HTTP and HTTPS in terms of security. (Comparison)
5. Name two protocols underlying HTTPS. (List)

---

### **Unit 3: Transport-Level Security - Topic 5: Secure Shell (SSH)**

#### **Definition and Context**

-   **Secure Shell (SSH)**: A protocol for secure remote login, file transfer, and network services over an insecure network, providing encryption, authentication, and integrity.
-   **Context**: SSH replaces insecure protocols like Telnet, offering secure access to servers and devices. Widely used for admin tasks, it’s documented in RFCs 4250–4256 (Page 23, "Unit 3.pdf").

#### **Key Features**

-   **Encryption**: Secures data in transit (e.g., passwords, commands).
    -   **Example**: Encrypting a remote server login session.
-   **Authentication**: Verifies user and host identities.
-   **Integrity**: Ensures data isn’t tampered with via MACs.
-   **Tunneling**: Supports secure forwarding of traffic (e.g., X11, TCP).
-   **Simplicity**: Lightweight compared to other secure protocols.
-   **Versions**: SSH2 fixes SSH1 flaws, is the standard (Page 23).

#### **SSH Protocol Stack** (Figure 6.8, Page 24)

-   **Transport Layer Protocol**: Handles encryption, integrity, and server authentication.
-   **User Authentication Protocol**: Verifies user identity.
-   **Connection Protocol**: Manages multiple logical channels (e.g., shell, file transfer).
-   **Example**: SSH session with encrypted terminal and file transfer channels.

#### **Transport Layer Protocol** (Pages 25–27)

-   **Functions**:
    -   Establishes secure connection with encryption and MAC.
    -   Authenticates server using public/private key pairs.
-   **Key Exchange** (Figure 6.9):
    -   Negotiates algorithms (e.g., AES, HMAC-SHA1) and keys.
    -   Uses Diffie-Hellman or similar for shared secret.
-   **Packet Formation** (Figure 6.10):
    -   Includes packet length, padding, payload, and MAC.
-   **Trust Models** (Page 25):
    -   Client stores server public keys locally.
    -   Keys certified by a trusted CA.
-   **Algorithms** (Table, Page 28):
    -   **Ciphers**: AES-128-CBC (recommended), 3DES-CBC (required).
    -   **MACs**: HMAC-SHA1 (required), HMAC-MD5.
    -   **Compression**: Optional (e.g., zlib).
-   **Example**: Server authenticates with RSA key, encrypts session with AES.

#### **User Authentication Protocol** (Page 29)

-   **Methods**:
    -   **Publickey**: Client signs with private key; server verifies public key.
        -   **Example**: SSH key pair for passwordless login.
    -   **Password**: Client sends encrypted password.
        -   **Example**: Typing password for SSH access.
    -   **Hostbased**: Authenticates client host’s private key.
        -   **Example**: Trusted host login for automated scripts.
-   **Example**: User logs into a Linux server with an RSA key pair.

#### **Connection Protocol** (Pages 30–32)

-   **Functions**:
    -   Multiplexes logical channels (e.g., shell, file transfer) over a single SSH tunnel.
    -   Supports flow control with windowing.
-   **Channel Types**:
    -   **Session**: Runs programs (e.g., shell, SFTP).
    -   **X11**: Forwards X Window System GUI.
    -   **Forwarded-tcpip**: Remote port forwarding.
    -   **Direct-tcpip**: Local port forwarding.
-   **Example**: SSH tunnel forwarding MySQL traffic from local to remote server.

#### **Port Forwarding** (Page 33, Figure 6.12)

-   **Purpose**: Converts insecure TCP connections into secure SSH tunnels.
-   **Types**:
    -   **Local**: Forwards local port to remote server.
        -   **Example**: Accessing a remote database via `ssh -L`.
    -   **Remote**: Forwards remote port to local machine.
        -   **Example**: Exposing a local web server via `ssh -R`.
-   **Example**: Tunneling RDP (port 3389) through SSH for secure remote desktop.

#### **Importance**

-   **Threat Mitigation**: Prevents eavesdropping, tampering, and unauthorized access.
-   **Admin Efficiency**: Secures remote server management and file transfers.
-   **Compliance**: Meets standards (e.g., PCI-DSS) for secure remote access.
-   **Versatility**: Supports diverse use cases (login, tunneling, automation).

#### **Exam Focus Points**

-   **Features**: Memorize encryption, authentication, tunneling (Page 23).
-   **Protocols**: Understand Transport, Authentication, Connection roles (Figure 6.8).
-   **Authentication**: Know publickey, password, hostbased methods (Page 29).
-   **Port Forwarding**: Grasp local vs. remote forwarding (Figure 6.12).
-   **Algorithms**: Focus on AES, HMAC-SHA1 (Table, Page 28).

#### **Potential Exam Questions**

1. What is SSH? List two security services it provides. (Short Answer)
2. Describe the role of the SSH Transport Layer Protocol. (Descriptive)
3. Explain one SSH user authentication method with an example. (Conceptual)
4. Differentiate between local and remote port forwarding in SSH. (Comparison)
5. Name two algorithms used in SSH encryption. (List)

---

#### Differences between SSL and TLS.

| **Aspect**                      | **Secure Sockets Layer (SSL)**                    | **Transport Layer Security (TLS)**                            |
| ------------------------------- | ------------------------------------------------- | ------------------------------------------------------------- |
| **Version Number**              | Uses SSL versioning (e.g., 3.0 for SSLv3).        | Distinct versioning (e.g., 3.1 for TLS 1.0, 3.3 for TLS 1.2). |
| **Message Authentication**      | Uses older MACs (e.g., ad-hoc MAC in SSLv3).      | Uses HMAC with stronger algorithms (e.g., SHA-256).           |
| **Pseudorandom Function (PRF)** | Weaker PRF based on MD5/SHA-1 concatenation.      | Robust HMAC-based PRF (e.g., HKDF in TLS 1.3).                |
| **Alert Codes**                 | Limited alert types (e.g., fewer error messages). | Expanded alerts (e.g., close_notify, bad_record_mac).         |
| **Cipher Suites**               | Supports weak ciphers (e.g., RC4, DES).           | Modern suites (e.g., AES-GCM, ECDHE); removes weak ciphers.   |
| **Client Certificate Types**    | Limited options (e.g., RSA-based).                | More options (e.g., ECDSA, DSS).                              |
| **Certificate Verify/Finished** | Weaker hashing for verification.                  | Stronger hashing (e.g., SHA-384 in TLS 1.3).                  |
| **Cryptographic Computations**  | Simpler key derivation (e.g., MD5/SHA-1).         | Advanced key derivation (e.g., HKDF in TLS 1.3).              |
| **Padding**                     | Vulnerable to attacks (e.g., padding oracle).     | Secure padding to resist attacks.                             |
| **Performance**                 | Slower handshake (2-RTT in SSLv3).                | Faster in TLS 1.3 (1-RTT handshake).                          |
| **Security**                    | Vulnerable to attacks (e.g., POODLE, BEAST).      | Mitigates attacks, enforces forward secrecy (TLS 1.3).        |
