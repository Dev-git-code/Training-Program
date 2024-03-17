
(Security+)[https://www.youtube.com/watch?v=O4pJeXgOJDs]

# CompTIA Security+ Full Course 

## Layered Security Concept
- Each layer or device can contain its won security methods. 
- If a breach occurs in one area of the network, the rest of the network will remain secure. 
- Application aware devices can be used to add another layer of security on the network. Application aware devices include firewalls, proxy servers, and IDS/IPS. 
### Unified Threat Management (UTM) security appliance
- A possible all-in-one security solution Contains firewall features. 
	- Contains IDS features. 
	- Contains antivirus and antimalware features. 
	- Contains anti-spam features.
	- Can perform content and URL (website) filtering.
- provides multiple security features in a central location, simplifies management of security, and eases updating security
- concentrates security in a single system or location, which can create a single point of failure for both the network and for security.
### Web Security Gateway

A **Web Security Gateway** is a system designed to protect networks from malicious content that is on the Internet. It serves several purposes:

- **Content Filtering**: It can filter out prohibited content, such as adult material, gambling sites, or sites containing malware.
- **Malicious Code Detection**: The system can scan incoming web traffic to detect and block malicious code, such as viruses, worms, or Trojans.
- **Data Loss Prevention (DLP)**: It can function as a DLP measure by scanning outgoing content. If sensitive data is detected, it is prevented from leaving the network.
### Protocol Analyzer

A **Protocol Analyzer**, often referred to as a **packet sniffer**, examines network behavior at a very basic level by analyzing individual packets of data. Its functionalities include:

- **Resource Consumption Analysis**: It allows monitoring to determine what is consuming network resources, such as identifying broadcast storms or detecting issues with network interfaces.
- **Network Breach Detection**: It can identify suspicious activity indicating a potential network breach or attack.
- **Study of Breach Methods**: Protocol analyzers are instrumental in studying the methods used to create network breaches.
- *Wireshark* is a widely used protocol analyzer in the field.
### Web Application Firewall (WAF)

A **Web Application Firewall (WAF)** is an application layer (Layer 7) firewall specifically designed to control HTTP traffic destined for web servers. Key points about WAFs include:

- **Enhanced Inspection and Control**: WAFs provide greater inspection and control over messages and traffic directed towards a network's web servers.
- **Protection Against Common Attacks**: They are configured to protect web servers from common attacks, such as SQL injection, cross-site scripting (XSS), and other web application vulnerabilities.
- **Focus on Web Server Protection**: Unlike normal network firewalls, which aim to protect the entire network, WAFs are concerned solely with regulating what is allowed to reach the web server.
## Integration of Data

- **Evaluation of Risks**:
	- Data may reside beyond the direct control of the business.
	- Network transmissions between parties may be vulnerable to interception or tampering.
	- The security measures on the third party's side may not be secure . 

- **Onboarding and Offboarding Processes**:
	- **Onboarding**: Establish procedures and systems to grant authorized individuals from the third-party partner access to relevant systems and data during the onboarding process.
	- **Offboarding**: Implement processes to revoke access promptly when the partnership is terminated or when authorized personnel leave the business partner.
	- Implementing an Identity and Access Management (IAM) system can streamline these processes.

- **Interoperability Agreements**
	- **Memorandum of Understanding (MOU)**:  establishes an agreement between two parties regarding the integration process, outlining their mutual understanding and commitments.
	- **Blanket Purchase Agreement (BPA)**:  created to cover repetitive needs for products or services, streamlining the procurement process for ongoing requirements.
	- **Service Level Agreement (SLA)**: specifies the guaranteed uptime of a system, outlining performance metrics and expectations regarding the quality of service.
	- **Internet Service Agreement (ISA)**: specifies any data limits placed on an Internet connection and guarantees the amount of uptime for the connection, ensuring reliability and performance.

- **Data Backups**
	- Cloud storage of data backups
	- All backups stored offsite should be encrypted to ensure data security and privacy, mitigating the risk of unauthorized access or breaches.

- **Data Ownership**
	- Before integrating systems and data with third parties, it's crucial to establish a clear understanding of data ownership. 
	- Ensure there's clarity on data ownership, as some third parties may consider all data stored on their systems as their own, irrespective of its origin.

- **Follow Security Policies and Procedures**
	- Implement security policies and procedures to prevent unauthorized sharing of data.
	- Define clear guidelines on what constitutes unauthorized data sharing to mitigate risks associated with data breaches or misuse.
## Application Attacks 
### Cross-site Scripting (XSS) Attack

- attacker inserts script code into a form on a web page, which is then submitted to the server. 
- server forwards the script code to another client system, where it gets executed. 
- often utilized to target database servers supporting web pages.
### SQL Injection Attack

- the hacker inserts SQL commands into the application, typically via an input field. 
- application then forwards these commands to the database application, enabling the modification of the database. 
- can include actions such as inserting a new username and password for further exploitation.
- Similar attacks: 
	- Uses the same principle as an SQL injection attack, but exploits LDAP calls instead of SQL commands.
	- Uses the same principle as the SQL and LDAP injection attacks, but exploits XML to modify the targeted application.
### Buffer Overflow Attack

- hacker sends more information than the application's memory buffer can handle, overflowing the buffer.
- The additional information will often be placed in memory outside of the buffer.
- If the hacker can get the right information stored outside of the buffer, he can execute code with administrative privilege.
### Integer Overflow Attack

- Similar to a buffer overflow attack, but involves exploiting the mathematical functions of an application.
- When a mathematical function returns an integer larger than the memory space that has been allocated to receive it, applications often respond in unexpected ways, this represents a security issue.
### Directory Traversal/Command Injection Attack

- hacker attempts to traverse the Web server's directories to the point where he  can execute commands on the underlying operating system (OS).
- attacker manipulates the URL requests in order to move through the directories and get to a command prompt on the underlying OS.
## Secure network Administration 

### Rule-Based Management Defined

- The implementation of rules at the technology level, used to create a secure network environment.
-  should be designed and tested to ensure that the rules function as expected.
### Firewall Rules

- firewall rules should be configured in such a way that only the required traffic is allowed to pass through.
- Whenever possible, the default rule should be to deny traffic. Exceptions are then created to allow the required traffic.
- The last rule on any firewall should be an implicit deny statement. Unless explicitly allowed, the traffic is denied entry into the network.
### Access Control List (ACL)

- Files and folders can have ACLs placed on them through the use of permissions.
- Routers can have two ACLs per network interface.
	- One ACL is on the inbound side of the interface.
	- The other ACL is on the outbound side of the interface.
- All ACLs end with an implicit deny statement. If not explicitly allowed in the ACL, the traffic or request is denied.
- Once created, the ACL should be tested for functionality to ensure that required actions are allowed and that non-required actions are not allowed.

![](https://i.imgur.com/8L4PMBQ.png)
![](https://i.imgur.com/2Rnkmi8.png)
![](https://i.imgur.com/Bp044Vl.png)
## Secure network Design 

### Demilitarized Zone (DMZ)

- specific area (zone) created usually between two firewalls that allows outside access to network resources (e.g., a Web server), while the internal network remains protected from outside traffic.
- The external facing router allows specific outside traffic into the DMZ, while the internal router prevents that same outside traffic from entering the internal network.
### Network Address Translation (NAT)

- technique used to allow private IP addresses to be routed across, or through, an untrusted public network.
- NAT device, usually a router, assigns a public routable IP address to a device that is requesting outside access.
- NAT has the added benefit of protecting the internal private network.
- The private network's IP addressing scheme is hidden from untrusted networks by the NAT enabled router.
### Network Access Control (NAC)

- method of controlling who and what gains access to a wired or wireless network.
- uses a combination of credentials-based security (e.g., 802.1x) and some form of posture assessment for a device attempting to log on to the network.
- A posture assessment considers the state of the requesting device. The device must meet a set of minimum standards before it is allowed access to the network.
- Common device assessments include the type of device, operating system, patch level of the operating system, the presence of anti-malware software, and how up to date it is.
### Virtualization

- process of creating virtual resources instead of actual resources.
- if the virtual resource is compromised, it can easily be taken down, covered, fixed, and then brought back online.
- Extesinble Authentication Protocol ( EAP ) must be used when allowing remote access. 
### Subnetting

- logical division of a network—a single block of IP addresses—into discrete separate networks.
- done to increase the security of the network by segmenting resources by needs and security level.
### Segmentation of Resources

- Security can be increased by segmenting a network based on resources and security needs through the implementation of virtual local area networks (VLANs).
- can be done based on user groups (e.g., a VLAN for the sales department and another one for human resources).
- can also be done based on resource type (e.g., a VLAN for file servers and another one for Web servers).
- use of VLANs supports a more secure, layered approach in the network design.

## End-to-end Security 

### IPsec (Internet Protocol Security)

- Works at Layer 3 of the OSI model and above.
- most common suite of protocols to secure a VPN connection.
- Can be used with the Authentication Header (AH) protocol. AH only offers authentication services, no encryption.
- Can be used with Encapsulating Security Payload (ESP). ESP both authenticates and encrypts packets (the most popular method).
- Both AH and ESP will operate in one of two modes.
	- Can be used in transport mode between two devices (e.g., the host-to-host VPN).
	- Can be used in tunnel mode between two endpoints (e.g., the site-to-site VPN).
- IPSec implements Internet Security Association and Key Management (ISAKMP) by default.
- ISAKMP provides a method for transferring security keys and authentication data between systems, outside of the security key generating process.
## Wireless Security 

### SSID (Service Set Identifier) Broadcasts

- A wireless access point (WAP) will broadcast the names (i.e., the SSIDs) of available networks.
- By default, the SSID is broadcast in clear text, creating a vulnerability.
- A best practice is to set the WAP to hide the SSID beaconing; this will prevent the casual user from seeing the wireless network.
- Even with the beacon set to be hidden, with the proper hardware and software, an attacker can still read the broadcasts.
### MAC Filtering

- All WAPs come with the ability to limit which Layer 2 MAC addresses can connect to the wireless network.
- While this can increase the security of the wireless network, MAC addresses can be spoofed.
- MAC filtering may not be appropriate in all situations.
### WEP (Wired Equivalent Privacy)

- An older encryption standard that utilized a pre-shared key (PSK) to encrypt messages between the WAP and the connecting device.
- Used the RC4 algorithm for the encryption.
- It is easily broken (cracked) and should not be used.
### WPA (Wireless Protected Access)

- An older encryption standard used as an intermediate replacement for WEP.
- Introduced TKIP (Temporal Key Integrity Protocol) as an additional security measure.
- TKIP creates a new security key for every packet that is sent.
- It can be broken and should not be used unless absolutely necessary.
### WPA2-Personal

- The current wireless encryption standard for the home or small business utilizing a PSK.
- Introduced Counter Mode Cipher Block Chaining Message Authentication Code Protocol (CCMP) with Advanced Encryption Standard (AES) as a means of addressing the weaknesses present in WEP and WPA.
- Cannot be easily cracked, but given enough time and computing resources, it can also be broken.
### WPA-Enterprise

- The current wireless encryption standard for larger businesses.
- Users are required to be authenticated before being allowed to connect to the wireless network.
- Authentication can occur using different methods that fall within the 802.1x standard.
- The WAP will pass requests to log on to an authentication server (commonly a RADIUS server) to authenticate the user before allowing access.
### Extensible Authentication Protocol (EAP)

- A common authentication protocol used by WPA2 to allow access to wireless networks.
- EAP packets are encapsulated within 802.1x packets, which are forwarded to an authentication server.
- LEAP (Lightweight EAP) is a Cisco proprietary method of implementing EAP. It was developed before the 802.1x standard was developed.
- PEAP (Protected EAP) is a method of encapsulating EAP packets with TLS in order to increase security.
### Other Methods 

- Captive portals can be used to require users to authenticate through a Web page when attempting to join a network. This is a common method used in publicly available wireless networks.
- VPN (virtual private network) over wireless can be used to further increase wireless security. Wireless network access must be through a VPN, adding an additional level of security in the network.

## Data backups 

- **Full Backup**
	- All data on the targeted system is backed up.
	- Slowest backup method with the highest storage requirements, but leads to the fastest recovery period.
	- Recovery only requires the full backup file.

- **Incremental Backup**
	- Only the new or modified files are backed up.
	- Fastest backup method with the lowest storage requirements, but leads to the slowest recovery period.
	- Recovery requires the last full backup file and all of the incremental backup files.

- **Differential Backup**
	- Only data that has changed since the last full backup is saved.
	- Time to backup is moderate, requires a moderate amount of storage, but also is the middle ground on the length of time for recovery.
	- Recovery requires the last full backup file and the last differential backup file.

- The configuration files of a network device should also be backed up. 
## Fault Tolerance 

### Server Fault Tolerance 

**Clustering**
- Taking a single server's responsibilities and spreading them across multiple servers (nodes).
- The active node is responsible for ensuring that the other nodes contain current copies of the data or processes. If a single node fails, operations continue uninterrupted.
- Has the advantage of allowing for load balancing.
- As all the nodes contain current information, during peak periods, the workload may be spread out among the various nodes.
- The cluster may be contained within a single facility, or it may be geographically disbursed (distributed).
### Hard Drive Fault Tolerance

- Most commonly achieved through the implementation of RAID (Redundant Array of Independent Disks).
- RAID may be used to increase performance, fault tolerance, or both performance and fault tolerance.
- Not all implementations of RAID involve fault tolerance.

#### Types of RAID

- **RAID 0 (Disk Striping)**
  - Data is striped across two or more disks, which leads to an increase in performance.
  - Not fault-tolerant.

- **RAID 1 (Disk Mirroring)**
  - Data is duplicated across two or more disks, which leads to fault tolerance.
  - Does not lead to an increase in performance.

- **RAID 5 (Disk Striping with Parity)**
  - Data is striped across multiple disks (three or more) along with a parity bit.
  - Is fault-tolerant and has performance close to that of RAID 0.

- **RAID 10 (Stripe of Mirrors)**
  - Requires four or more disks, as it includes a mirror set and a stripe set.
  - Has the best performance and is fault-tolerant.
## Confidentiality, Integrity, and availability controls

### Confidentiality

- **Access Control/Permissions**
  - Explicitly establishing who can access the information.
  - The person requesting access must have explicit permission to do so.

- **Encryption**
  - Using an algorithm to make data unreadable unless the appropriate security key is present.
  - Encryption can be placed at multiple levels (e.g., file level, storage level, or the communication channel level).

- **Steganography**
  - Concealing data (e.g., a text file) within a graphic file.
  - The person receiving the graphic file must use steganography software to read the secured data.
  
- *In many cases, access control/permissions and encryption are used together to increase the confidentiality of data or systems.*
### Integrity

- **Hashing**
  - Using a mathematical algorithm to verify that no change has occurred to the data in transit.
  - Once received, the hashed value of the data is used to ensure that integrity has been maintained.

- **Certificates**
  - A cryptographic means of transporting or exchanging security keys.
  - Ensures the integrity of the security keys.

- **Digital Signatures**
  - Using a combination of certificates and security keys to authenticate the sender of a message or data.
  - Ensures the integrity of the source.

- *Integrity controls are often used in conjunction with confidentiality controls.*
### Availability

- **Fault Tolerance**
  - Ensuring that even in the case of a failure, data is available.
  - Can be achieved through multiple methods (e.g., RAID or server clustering).

- **Redundancy**
  - Ensuring that systems are always available by using multiple units.
  - Using a partial mesh topology to guard against the failure of a network switch.

- **Backups**
  - Ensuring that data can be recovered in the case of loss or corruption.

- **Patching**
  - Ensuring that systems and data are available by keeping operating systems and configuration files up to date.
  - A safeguard against common system attacks.
## Types of Malware and Attacks 

### Virus

- Malware that has two jobs to replicate and to activate.
- Requires a host program, a host machine, and user action to spread.
- Viruses only affect drives (e.g., hard drives and USB drives).
- Often contains a destructive payload.

### Trojan

- Malware that hides its purpose by disguising itself as something that the end user desires.
- Used to get the end user to download a virus package.
- This is often the method that is used to establish botnets or zombie nodes.

### Worm

- Similar to a virus, but it replicates itself across a network without user action.
- It doesn't need a host file in order to operate.
- Worms will replicate themselves across networks, creating havoc.

### Rootkit

- A software package that gets installed on a system, giving the attacker privileged access to the system.
- Most often, the attacker attempts to hide the rootkit from the administrator.

### Logic Bomb

- A virus that, after getting installed on a system, waits for a specific event to occur before activating its payload (performing its malicious action).
- The application carrying the logic bomb will function normally until the trigger event occurs.
- Often, logic bombs are triggered by date and time.

### Ransomware

- A virus package that takes over an infected system for the purpose of extorting money from the end user.
- Often, the virus will encrypt all the files and folders on the infected system, effectively locking out the end user.

### Botnet

- A collection of infected systems (zombie nodes) under the control of the attacker.
- The zombies are used to perform other attacks.
- The zombie controller will often rent out the use of a botnet for other attackers to use.

### Adware

- A software package designed to automatically load advertisements on a system—usually in the form of pop-up windows.
- The goal is to entice users to purchase something, but the result is usually just annoyance and poor system performance.

### Spyware

- Malicious code that collects information about the system and may change some settings.
- May be programmed to send the collected information to an attacker at specific times.
- May be programmed to save the collected information until the attacker performs another action.

### Polymorphic Virus

- A virus package that self-mutates in order to avoid detection by antivirus applications.
- Allows the virus to avoid signature-based malware detection.

### Armored Virus

- A virus package that attempts to harden itself against defensive actions, making it difficult to be decompiled.
- Antivirus vendors often decompile (take apart) viruses when developing countermeasures.

### Backdoor Access

- When creating applications, developers often create backdoors into the programs.
- Backdoors are a means of accessing an application or service while bypassing the normal authentication process.
- Malware can also be used to open a backdoor into a program, a computer system, or even a network.

### Privilege Escalation

- Attempting to raise a user's account privileges to an administrative level, giving them access to almost everything.
- Usually occurs due to a vulnerability that may be present in the operating system itself; however, the vulnerability may also be present in another piece of software.
- The best defense is to remove all known vulnerabilities from operating systems and software.

### ARP Cache Poisoning (Address Resolution Protocol)

- The ARP cache, which maps IP addresses to MAC addresses, is corrupted by an attacker with the end result being that the attacker has control of which IP addresses are associated with MAC addresses.
- Commonly used in man-in-the-middle attacks.

### Client-side Attack

- An attack on a system through vulnerabilities that may be present within software on a client system.
- Attacks often originate from Internet applications or messaging applications.

### Replay Attack

- An attack that uses a packet sniffer to capture network session data.
- The attacker then re-submits the captured packets in an effort to gain access to the network.

### Transitive Access Attack

- The attacker attempts to get a user to click on a hyperlink to an MS Windows shared folder.
- If the user clicks on the hyperlink, the user's system is forced to send the user account credentials, allowing the attacker to attempt to get access to valid credentials.

### Man-in-the-Middle (MitM) Attack

- The attacker is not necessarily inside the network per se but is in between two endpoints that are communicating on a network.
- The attack allows a malicious user to be able to view all network packets that are flowing between the communicating hosts.

### DNS Poisoning

- The attacker changes the DNS records for a specific website in order to redirect traffic to a malicious website.
- The change in record can either be on the local DNS apparatus, or it may occur at a higher level (e.g., at the Internet service provider level).

### Typo-squatting (or URL Hijacking)

- The attacker sets up malicious websites using common misspellings of legitimate URL (Uniform Resource Locator) names.
- The attacker assumes that a certain amount of traffic will reach the malicious website merely due to user error.

### Watering Hole Attack

- The attacker compromises (e.g., plants malicious code on) a legitimate trusted website.
- As users visit the trusted site, malicious code is executed.

### DoS (Denial of Service) Threats

- Covers a very broad category of threats to networks and systems.
- Any threat that can potentially keep users or customers from using network resources as designed can be considered a type of DoS threat.

- **Permanent DoS Attack**
- An attempt to permanently deny a network resource for others, it can be done by physically destroying a resource or by damaging (or corrupting) the underlying operating system.

- **Traditional DoS Attack**
- An attempt to flood a network with enough traffic to bring it down—commonly used with malformed ICMP requests.

- **Distributed DoS (DDoS) Attack**
- A DoS attack in which more than a single system is involved in sending the attack, a botnet is often used to implement the attack.

- **Smurf Attack or Smurfing**
- A network is flooded with ICMP requests in which the source address for the requests appears to be that of the intended target (it has been spoofed).

### Sniffer and Password Attacks 

- **Dictionary attack:** The attacker uses specialized software containing popular usernames and all words in a language to attempt all possible combinations to find a working password.
- **Brute force attack:** The attacker uses a password cracking application to mathematically calculate every possible password combination, requiring significant computing power and time for success. A rainbow table may expedite the process by containing all possible characters and combinations.
- **Hybrid attack:** combines the dictionary attack and brute force attack techniques.
- **Birthday attack:** An attempt to duplicate a hashed value used for authentication. The attacker hashes data to recreate a known hashed value, eventually duplicating it with enough input data.

### Phishing Attacks

- **Email Phishing:** Attackers send deceptive emails pretending to be from legitimate sources, tricking recipients into divulging sensitive information or clicking on malicious links.  
- **Spear Phishing:** A targeted form of phishing where attackers tailor messages to specific individuals or organizations, often using personal information to increase credibility and success rates.
- **Vishing:** Phishing attacks conducted over voice calls, where attackers impersonate trusted entities to trick victims into revealing personal or financial information.

## Wireless Attacks 

### War driving/war chalking

- The practice of attempting to sniff out unprotected or minimally protected wireless networks.
- Marks are placed on buildings and streets, indicating vulnerable networks.
- Vulnerability arises because wireless networks broadcast over the air.

### Rogue access point attack

- Involves installing an unauthorized wireless access point (WAP) on the network.
- Often done by end users for convenience, creating network vulnerabilities.
- Can also be implemented by hackers.

### Jamming attack

- Interferes with wireless networks' radio frequency (RF) channels, rendering them unusable.
- Frequently used in DoS attacks or as a prelude to other attacks.
- Modern networking standards and devices employ countermeasures against jamming.

### Evil twin attack

- Installs a WAP with an SSID similar to an authorized network.
- Captures users' keystrokes to gain sensitive information.
- Can be considered a form of wireless phishing attack.

## Weaknesses in some applications 

### Cookie

- Text file used by web developers to store user information locally.
- Captured cookies may reveal sensitive information, leading to exploits.

### Flash cookie/Locally Shared Object (LSO)

- Method used by Adobe Flash programmers to store information on users' computers.
- LSOs can track user Internet activity, posing a privacy threat.
- LSOs often persist on a user's system even after other cookies are deleted.

### Attachment

- A file attached to an email message.
- Commonly used as a threat vector to deliver malicious applications.

### Malicious add-on

- Software installed into browsers for additional features.
- Add-ons causing browser performance deterioration or exploiting vulnerabilities are considered malicious.

### Header manipulation

- Hackers modify header data of applications to change their functionality.
- Used to alter how a web server processes information and conceal information in file headers.

### Session hijacking

- Usually combines both a network and an application attack.
- The hacker waits until a communication channel has been opened between at least two parties (e.g., an administrator signing in to a web server) and then disconnects one of the parties and inserts themselves into the communication channel.
- The attacker typically uses a DoS (denial of service) type attack to disconnect one of the parties.
- Once inserted into the communication flow, the hacker attempts to gain control of either sensitive information or of the application itself.

## Network Security enhancement techniques

### Monitoring system logs

- Event log: records system events that usually require user interaction
- Audit log: a summary log file of other log files that has been configured by an administrator to record and report significant events
- Security log: records security events that have occurred on the system.
- Access log: most network devices can log who has accessed the system and when the access occurred.

### Hardening individual systems

- Security personnel should strive to harden all systems against attacks
	- Disable unnecessary services.
	- Disable unnecessary user accounts
	- Protect management interfaces and applications.
	- Use password protection on all critical systems

### Employ network security measures

- Security personnel should strive to harden all networks against attacks.
- Implement MAC limitations and filtering on switch and router interfaces.
- Disable all unused switch and router interfaces.
- Whenever possible, use strong authentication protocols (eg.. 802.1x).
- Conduct periodic site surveys, both wireless and wired, to detect and remove rogue (non-authorized) systems.

### Establish a security posture

- An initial baseline of the security configuration must be created and reviewed on a periodic basis. All systems brought online must meet or exceed the initial security baseline.
- Continuous security monitoring should be conducted to ensure that all systems continue to meet or exceed the baselines that have been established.
- As new vulnerabilities become known, they must be removed (remediated) and the security baseline updated.

## Security Assessment 

### Assessment techniques

- **Baseline reporting:** using a baseline how the system operates under normal conditions-after an incident has occurred to help determine what may be causing system issues. 
- **Code review:** having a security tester review and analyze application code developed by in-house programmers before deploying an application.  
- **Attack surface review:** having a security expert review all of the software and services (the attack surfaces) that are running on any system.The goal is to remove any unnecessary software or services to reduce the attack surfaces that are present.
- **Architecture review:** a review of the underlying structure (architecture) to ensure that all applications and services operate in the correct manner (e.g., determining that an application does not have access to kernel code). 
- **Design review:** a careful review of systems and solutions from a security point of view.
	- Should be done before implementation-secure by design.
	- Should be conducted after implementation to ensure that what was requested (designed) was actually implemented.
### Assessment Tools 

#### Protocol analyzer (packet sniffer)

- A tool that will passively collect information that is traversing the network. It can be used to determine what systems and processes are in operation.
- One goal, when used for security purposes, is to determine if sensitive information is being transmitted in clear text.

#### Port scanner

- A tool that will actively scan the network for the status of ports.
- One goal, when used for security purposes, is to determine if any vulnerable ports are open (easy to exploit), so they can be closed.

#### Vulnerability scanner

- A tool that is similar to the port scanner, but is actively searching the system for known vulnerabilities.
- It will not only check for open ports, but it will also verify configurations and patch levels.
- It checks the scan results against a database of known vulnerabilities.

#### Banner grabbing

- Often used in conjunction with a port scan or vulnerability scan type assessment.
- When used with either the port or vulnerability scan, it will return what software (and which version of it) is operating on the open port.
- The information returned can be used to determine if the open port truly represents a security issue.

#### Honeypots and honeynets

- A computing system or network established with the sole purpose of attracting any hackers who breach the network.
- They have a high level of auditing in place in order to help determine how the hacker entered the system and any actions that the hacker engaged in while in the system.
- The actual assessment of the results of hacked honeypots/honeynets is used to further harden the legitimate system.

## Vulnerability Scanning 

- **Purpose**: The purpose is to assess the configuration of systems and networks to determine what can be done to increase the level of security.
- **Method**: This is done passively by collecting information and reporting on the information collected in a non-intrusive manner.
- **Identified Issues**: The scan can help to identify different issues such as lack of security controls, common misconfigurations (in applications and devices), and other vulnerabilities.
- **Types of Scans**:
  - **Credentialed Scan**: Conducted from an administrative account to assess the system as an authorized user.
  - **Non-credentialed Scan**: Conducted as an unauthorized user to determine what information an unauthorized user may find out about the system.
- **False Positives**: A false positive may be reported by vulnerability scans, which refers to something reported as a vulnerability that isn't actually one.

## Penetration Testing 

- The purpose is to assess the security of a system or network by actually using the same methods that a hacker would use to breach security.
- The test can be used to verify that a threat exists. It can also confirm that the threat doesn't exist.
- The test seeks to actively test and bypass any security controls that may be present.
- It is designed to exploit any vulnerabilities that may be present on the system or network.
- Unauthorized pen testing may lead to legal issues.
- types of testing: 
	-  White box testing: Tester has exact details of the system or network configuration.
	- Gray box testing: Tester has intermediate knowledge of system or network configuration.
	- Black box testing: Tester has no prior knowledge of the system or network configuration.


## Application security controls and techniques 

### Error handling

- Thoroughly testing applications will catch most errors, with the possible exception of some runtime errors.
- Runtime errors are problems that occur during the operation of an application.
- Many things can cause a runtime error, including poor programming, conflicts with other software (including malicious applications), and conflicts with hardware.
- The developer should put processes in place that trap all runtime errors before such an error crashes the application.
- Trapping a runtime error requires that the developer intercept the error and display a warning message before the error causes the application to crash.

### Exception handling

- A more advanced method of error handling.
- An exception is a different term for a runtime error.
- Exception handling code will use a try/catch block to try this code and catch any errors that occur.
- Usually will provide a means of looping the program until the error condition subsides.

### Client-side and server-side validation

- Initial input validation should occur on the client (requesting machine) before it is sent to the application on the server.
- This can help to prevent a runtime error or exploit on the server and reduces the amount of traffic that is crossing a network.
- Additional input validation should occur at the server (receiving machine) before the input is passed on to the application, further reducing the chances of a runtime error or an exploit occurring.

### Cross-site scripting (XSS) prevention

- XSS occurs when a hacker inserts script code into a form on a website so that when other users access the form, the script is executed.
- Proper input validation of data is usually an effective means of preventing XSS from occurring.

### Cross-site request forgery (XSRF) prevention

- XSRF is when a user is automatically directed to a linked Web page and logged in using data supplied by a cookie from the original page when this was not the Web developer's intent.
- Web developers can help to prevent XSRF from occurring by setting a short expiration time for cookies.
- Users can help prevent XSRF by choosing not to have a website automatically log them in when they visit the site.

### Application configuration baseline

- The initial setting up of an application (the baseline) should be done with security in mind.
- The baseline should be as secure as possible.

### Application hardening

- Disabling all features and functions that users should not be allowed to use (e.g., disabling an application's ability to use FTP).
- Should initially be done during the configuration process.

### Application patch management

- New exploits and threats against applications are created all the time, requiring that applications be updated on a regular basis.
- Patches are used to fix problems (e.g., security issues) that were unknown at the time the application was developed.
- Caution: just as with operating system patches, application patches must be tested before being deployed into a production setting.

### SQL vs. NoSQL databases

- SQL databases are the most common relational database management system used today.
- They are optimized for the inserting and updating of records in a database.
- NoSQL databases are designed to store and retrieve large amounts of data—big data.
- They must be optimized for the retrieval of big data and require different methods of input validation than a SQL database.

## Hardening Physical Hosts 

- Trusted OS: using an OS that implements multiple layers of security by design (e.g., requires authentication and authorization before granting access to host resources).
- Whitelisting applications: only applications that are specifically designated in the whitelist are allowed to run on the host.
- Blacklisting applications: explicitly denying (blocking) named applications from being run on a host.
- Host-based firewalls: using host-based firewalls to control what network traffic can be allowed into or out of the host. Especially important for mobile devices.
- Host-based intrusion detection system (HIDS): implemented to monitor the host to help detect when an intrusion has occurred to help minimize (or contain) any damage.
- Host software baselining: baselining software can be used to ensure that all OSs and applications on a host meet or exceed the minimum level of security that is required.

## Hardening Virtual Hosts 

- Snapshot: an image of the virtual host created at a point in time when that host is secure. It can be used to quickly revert the virtual host in cases where security has been compromised, can also be used to bring new hosts into service quickly and efficiently as needed, creating elasticity in the system.
- Patch management: same consideration as with physical hosts.
- Host availability: high availability methods should be used to ensure that virtual host systems are available to users as needed, removing single points of failure.
- Security control testing: separate security testing should be conducted on virtual systems to ensure that they operate as expected.
- Sandboxing: when high security is needed, a sandboxed environment can be created. Creating a virtual environment in which the virtual machines are restricted to what they have access to.

## Controls for data security 

### Data encryption

- **Full disk encryption**: All of the contents of the storage drive are encrypted. To access anything on the drive, the proper key must be input.
- **Database encryption**: Sensitive information contained in databases (e.g., customer credit card numbers) should always be kept in an encrypted format.
- **Individual file encryption**: If full disk encryption is not used, then all sensitive files should be encrypted.
- **Removable media encryption**: When data is allowed onto removable media, controls should be put in place to ensure that it is always encrypted on that media.
- **Mobile device encryption**: Because of their nature (highly portable and prone to loss), all mobile devices that are allowed to contain organizational data should also implement device encryption.
### Hardware based encryption

In most cases, hardware based encryption (encryption solutions built into the device) will outperform software based encryption solutions as the chipset in the device is optimized to perform the necessary algorithmic calculation.

- **TPM (Trusted Platform Module):** A specialized chip is used on the motherboard (which must be supported by the BIOS) to contain the cryptographic keys and perform the encryption.
- **HSM (Hardware Security Module):** A specialized add-on card is installed into the system to perform the hardware encryption.
- **USB and portable hard drive encryption:** When data is allowed onto portable media, only devices that support encryption should be used (e.g., an Iron-key flash drive).

### File and folder permissions

File and folder permissions are a method of specifying who can access files and folders (through authentication) and what manipulations can be performed on the data (through authorization) once it has been accessed. Permissions are usually established through the use of a type of ACL (access control list).

## Risk Mitigation Techniques

### Segmentation

Segmentation is a network design element in which resources are separated by function and security requirements into their own networks. It can be used to control communication and security within the network.

### Security layers

Placing security at different places and levels within a network will increase the security of the network as a whole. If one layer of security is breached, attackers will find another layer waiting to frustrate them, like the layers of an onion.

### Application firewalls

Application firewalls can be used to filter traffic based on what applications are allowed to operate on the network and which are not allowed to work on the network.

### Updates

Patches and system updates should be used to help keep computing environments secure. A best practice is to use a manual updating process so that proper testing of the update can be done.

### Firmware version control

Updates to firmware should be done if they will lead to an increase in security or in vital functionality.

### Wrappers

Wrappers are a host-based ACL that can be used in conjunction with a firewall to increase the effectiveness of security. Found in Linux and UNIX environments, they can be used to specify how an individual host can access a specific service (e.g., allowing Bob access to SCP but not to FTP on the file server).

## Authentication Services 

### RADIUS (Remote Authentication Dial-In User Service)

- Used for authenticating remote users and granting them access to authorized network resources.
- Popular AAA protocol ensuring only authenticated end users access authorized resources.
- Robust accounting features.
- Only the requester's (end user's) password is encrypted.

### TACACS+ (Terminal Access Controller Access-Control System Plus)

- Used for authenticating remote devices and granting them access to authorized network resources.
- Popular AAA protocol ensuring only authenticated remote network devices access authorized resources.
- Accounting features not as robust as RADIUS.
- All transmissions between devices are encrypted.

### Kerberos

- Authentication protocol, which uses TCP or UDP port 88.
- A system of authentication and authorization that works well in environments with many clients.
- The Key Distribution Center (KDC) is the main component.
- The KDC consists of two parts: the Authentication Server (AS) and the Ticket-Granting Service (TGS).
- When a user logs in, a hash of their username and password is sent to the AS. If the AS approves the hash, it responds with a Ticket Granting Ticket (TGT) and a timestamp.
- The client sends the TGT with timestamp to the TGS.
- The TGS responds with a service ticket (also known as an access token or just a token).
- The service ticket (token) authorizes the user to access specific resources.
- As long as the TGT is still valid, the TGS will grant authorization by issuing a new service ticket.

![](https://i.imgur.com/dgjJhS0.png)

### LDAP (Lightweight Directory Access Protocol)

- A directory service protocol used to authenticate clients.
- LDAP requests are sent over TCP port 389.
- Applications that are LDAP compliant will validate (authenticate) the client and then retrieve the requested information stored in the directory.
![](https://i.imgur.com/ipEdkGK.png)

### Secure LDAP

- Encrypted version of LDAP using SSL (Secure Socket Layer) over TCP port 636.
- All communication between the client and LDAP is secure.

### SAML (Security Assertion Markup Language)

- An XML (Extensible Markup Language) standard used to allow systems to exchange authentication and authorization information.

## Identification, Authentication, and Authorization 

- Identification is when an entity specifically declares who or what it is in a manner in which the receiving party understands. When the entity is a person and the receiving party is a computer, the most common form of identification is a username

- Authentication is a process where the identifying party offers some form of credentials to validate the identification (e.g., supplying a password with the username).

- Authorization is what the authenticated entity is allowed to access or the actions that may be taken (eg., authorization to access the FTP server and modify files on that same server).

### Authentication Concepts

#### Multifactor authentication

Requiring more than one of the authentication factors to be present before the authentication process can be completed.

- Username and password is a single factor authentication method, as these both come from the "something you know" category.
- Requiring a username, password, and a fingerprint scan is a two-factor authentication method (something you know combined with something you are).
#### Single sign-on (SSO)

 Requiring the user to identify and authenticate only once to achieve access to all authorized services within a network. In the past, every time a user needed access to a resource, that resource was required to authenticate the user before authorizing the access.
 
#### Identity federation

- SSO method used in organizations with multiple networks that allows authenticated users to sign on once and receive access to authorized resources across all of the organization's networks.

#### Transitive trust authentication

- The process of authenticating an entity based on that entity already being authenticated by a security entity that is trusted.
- For example, X is authenticated by organization T, but is requesting authentication from organization A (A doesn't know X).
- Since organization A trusts the security of organization T, A will authenticate X automatically.

#### Access control

The process of establishing specifically who or what can be authenticated and how that authentication will be done before authorization is granted to resources.

- **Implicit deny**
  - All access is automatically denied until the authentication process has been completed.

- **Trusted OS (operating system)**
  - Used to denote an OS that uses multiple layers of security (authentication and authorization) before access is granted to resources on the system.

#### HMAC (Hashed-based Message Authentication Code)

- A secret key, known to both parties, is combined with an algorithm to create the message authentication code (MAC).
- Provides an authentication check-verifying the identity of the sender-as well as an integrity check of the data.
- The MAC is the resulting hashed value.

#### HOTP (HMAC-based One-Time Password)

- An HMAC-based algorithm is used to create the password used for authentication purposes.
- Often used by authentication servers.

#### TOTP (Time-based One-Time Password)

- An authentication process for creating passwords based on the current time.
- An algorithm combined with a shared secret key and the current time generates a one-time password. It is a type of HOTP.
- Commonly used with security tokens for two-factor authentication.

#### PAP (Password Authentication Protocol)

- When logging into a network resource, the user or device supplies a username and password.
- The username and password are sent in clear text format, making this method unsecure and suitable only as a last resort.

#### CHAP (Challenge Handshake Authentication Protocol)

- When logging into a network resource, the user or device is challenged to supply a username and secret password, authenticating through a three-way handshake process.
- The resource issues a challenge, asking for the hashed value of the username and secret password (the HMAC).
- The user's device sends the hashed value to the resource device.
- The resource evaluates the hashed value and either accepts or rejects the connection.

#### Token

- Utilizes a TOTP (usually generated every 30 to 60 seconds) to authenticate users via two-factor authentication.
- May be hardware-based (e.g., attached to a key fob) or software-based (e.g., an app on a smartphone).

#### Smartcard

- Utilizes a card, usually credit card-sized, with an embedded circuit and a PIN (personal identification number), to provide two-factor authentication.

#### Common Access Card (CAC)

- A type of smartcard issued by the US military for identification and authentication purposes.
- Used to authenticate users on military networks.
- Used to encrypt and digitally sign electronic messages.

### Authorization concepts 

#### Separation of duties

- The process of taking a critical organizational task and separating it into smaller jobs.
- No one person is allowed (authorized) to perform all of the duties that make up the task, reducing the risks that can arise from a malicious employee.

#### Principle of least privilege

- Only granting the minimum amount of rights and privileges (authorization) required for employees to perform their jobs.
- Reduces the risks associated with either a malicious employee or a compromised user account.

#### Time of day restrictions

- Establishing technological controls that limit what actions may be taken based on time (e.g., preventing employees from logging on to the network outside of operating hours).

#### Rule-based access control (RBAC)

- The creation of rules within a system that either allow or disallow authorization to perform actions based on the rule.

#### ACL (Access Control List)

- A type of RBAC implementation used for authorization purposes, typically in the form of a list of rules.
- The list is typically examined from top to bottom; once a rule is matched, the corresponding action is taken. If no rule is matched, the typical response is to deny authorization.

#### Role-based access control (RBAC)

- A process of creating authorization levels based on the role (e.g., user group) that a person fulfills within an organization.
- Different roles will have different authorization levels, allowing the people who fill those roles to perform different duties.
- Most often implemented using the principle of least privilege.

#### Discretionary access control (DAC)

- A technological control used to determine authorization to resources based on a specific list—the discretionary access control list (DACL).
- The DACL is a listing of users and groups granted access (authorization) to resources.
- The DACL also determines the amount of access (what actions can be taken based on permissions) that the user or group has to the resource.

#### Mandatory access control (MAC)

- An access control model in which each individual (known as a subject) is assigned to a clearance level (e.g., top secret or confidential).
- Authorization to resources is based on the resource's classification (e.g., top secret or confidential).
- The subject is usually granted automatic authorization for resources that fall below their clearance level (e.g., a top secret clearance will always be able to access resources classified as secret).

## Cryptographic services

- The process of deriving a code value from a set of data-taking a clear text message and creating a ciphertext message. Also, the process of decoding the ciphertext message to obtain the clear text message. 
- Offers three basic services encryption, hashing, and authentication.
### Encryption services

- The process of taking a clear text message (or set of data) and scrambling it through the use of a cipher an algorithmic process.
- Used to secure messages and data sets against theft or loss, including its interception while in transit. 

### Hashing services

- The process of taking a set of data and using an algorithmic process to generate a value (known as the hashed value or message digest) that only the original data value can generate.
- The hashed value is generated and is appended to the data, used to help ensure the integrity of the data.
- If the data, with the hashed value, is sent to another party, that party can use the same hashing algorithm on the data and compare the two hashed values.
- If the two hashed values match, the integrity is ensured.

### Authentication services

- A cryptographic method used to prove that the creators of messages are indeed who they say they are.
- Used for non-repudiation purpose, the person sending the message, once authenticated, cannot claim that the message did not come from him or her.
- Usually achieved through the use of digital signatures.

## Encryption 

- Encryption algorithms work by using a key to scramble the data (or message), making it unreadable if intercepted.
- Encryption algorithms are either symmetrical or asymmetrical in nature.
- With symmetrical encryption algorithms, both sides of the communication use the same key to encrypt and decrypt the data.
- With asymmetrical encryption algorithms, one key is used to encrypt the data and a different key is used to decrypt the data (the key that encrypts the data cannot be used to decrypt it).
- Asymmetrical encryption is more secure, but it also requires more management and computing resources.

### Encryption key exchange

- In order for encryption to function between different entities, the proper keys must be used (e.g., exchanged between the communicating parties).
- The key exchange may occur in-band as part of the communication session.
- The key exchange may occur out-of-band outside of the data communication channel (e.g., sharing the encryption key over the phone, then sending encrypted data over the Internet).

### Key types

- **Symmetrical encryption key types**
  - Preshared key (PSK): The encryption key is shared before the communication session starts—out-of-band key exchange (a PSK can also be called a secret key or private key).
  - Session key: A random key that is generated during the communication session—in-band key exchange.
- **Asymmetrical encryption key type**
  - Uses a public key and a private key system referred to as public key infrastructure (PKI) to manage the keys—in-band key exchange.

### Basic encryption methods

- **Stream cipher**: The encryption occurs one bit at a time. The encryption process is fast and, if an error occurs, it will usually only affect a single bit.
- **Block cipher**: The encryption takes place on predetermined blocks of data (e.g., 64-bits at a time). The encryption process is slower and more error-prone, but is considered to be more secure than the stream type method.
  
### Steganography

- The process of encoding (or concealing) data within a graphic file.
- The person receiving the graphic file must use steganography software to read the secured data.
- Can be used to place an encoded message on a graphic image on a website that the recipient can retrieve and decode.

### Transportation encryption

- It may be vital that certain information flowing across public networks (e.g., the Internet) be kept secure during the transportation process.
- It may also be wise to provide security when using communication channels on private networks.
- Specific protocols have been developed to help secure communication channels.

- **HTTPS (HTTP Secure)**
  - Used to encrypt communication between a Web server and a client (utilizes SSL or TLS to provide the encryption).

- **SSL/TLS (Secure Socket Layer/Transport Layer Security)**
  - Used to encrypt communication channels, usually at the transport layer (Layer 4) of the Open Systems Interconnection (OSI) model.

- **S/MIME (Secure/Multipurpose Internet Mail Extension)**
  - Used to encrypt email messages.

- **IPsec (Internet Protocol Security)**
  - A suite of protocols used to authenticate users and encrypt the communication channel.

### Hashing 

- Hashing algorithms do not work on the header of a file.
- No matter how many times the header of the file changes (e.g., changing the name of a file), the hashed value of the data remains the same.
- The hashed value returned is a fixed length that depends on which algorithm is used. A specific algorithm will always generate the same size hash.
- It is theoretically possible to recreate a hashed value by running enough data through the hashing algorithm. When two hashed values are the same, it is called a collision. This is the concept behind a birthday attack.
- Common Hashing Algorithms 
	- MD (Message Digest): created by Ron Rivest.
	- MD5 is the current standard used and always returns a 128-bit hashed value.
	- SHA (Secure Hash Algorithm): created by the National Security Agency (NSA).
	- SHA-1 is the most popular version of SHA and returns a 160-bit hashed value.
	- SHA-256 is a newer version that returns a 256-bit hashed value.
	- SHA-512 is also a newer version that returns a 512-bit hashed value.

## Cipher Suites

A cipher suite combines cryptographic algorithms and protocols to ensure security in network communication. It includes user authentication, encryption, and message authentication. The suite's strength is determined by key length, with longer keys indicating stronger security.

### CHAP (Challenge-Handshake Authentication Protocol)

- A cryptographic authentication protocol used to authenticate remote clients based on hashed values.
- Clients combine their password with a key supplied by the server to generate a hashed value using MD5.
- The hashed value is sent to the server for comparison with a stored value.
- If matched, the client is authenticated and given access to authorized resources.
- Considered a type of HMAC (Hash-based Message Authentication Code).

### RIPEMD (RACE Integrity Primitives Evaluation Message Digest)

- A cryptographic hashing algorithm developed as an open source solution.
- Most common version is RIPEMD-160 (160-bit hashing function), with versions of 128, 256, and 320 bits.

### NTLMv2 (NT LAN Manager version 2)

- A cryptographic hashing process used in Windows operating systems for storing passwords in the registry.
- Uses HMAC-MD5 as the method of creating and storing the message digest.
- Replaced NTLM, which used MD4 as the hashing algorithm for the HMAC.

### MD (Message Digest)

- A cryptographic hashing algorithm developed by Ron Rivest for authentication purposes.
- MD5 is the most popular version, generating a 128-bit hashed value.
- MD5 is considered broken and unsuitable for critical security needs.

### SHA (Secure Hash Algorithm)

- A cryptographic hashing algorithm developed by the NSA.
- SHA-1 generates a 160-bit hashed value, but is theoretically broken.
- SHA-2 is now preferred by most government agencies for improved security.

## Cryptographic Implementations

### One-time pad (OTP)

- Asymmetrical cryptographic encryption method using a random security key for each message, resistant to hacking.
- Key changes with every message, making decryption difficult.

### DES (Data Encryption Standard)

- Asymmetrical cryptographic encryption standard developed by the US government.
- Utilizes a 56-bit encryption algorithm, considered insecure.

### 3DES (Triple DES)

- Improved version of DES using three separate 56-bit encryption keys for 168-bit encryption.
- Each data block encrypted three times with different keys.

### RC (Rivest Cipher)

- Family of symmetrical cryptographic encryption methods developed by Ronald Rivest.
- RC4: Weak stream cipher used by SSL and WEP.
- RCS: More secure block cipher algorithm.

### Blowfish

- Asymmetrical cryptographic encryption method developed by Bruce Schneier.
- Variable encryption bit length, ranging from single bit to 448-bit encryption.

### TwoFish

- Asymmetrical cryptographic encryption method by Bruce Schneier.
- Utilizes 128-bit encryption.

### AES (Advanced Encryption Standard)

- Asymmetrical cryptographic encryption method developed by NIST.
- Block cipher encryption method with a 128-bit block size.
- Key lengths of 128, 192, or 256 bits.

### RSA (Rivest Shamir Adleman)

- Asymmetrical cryptographic encryption method using public and private security keys.
- Public key used for encryption, private key for decryption.

### PGP (Pretty Good Privacy)

- Asymmetrical cryptographic encryption method for generating and publishing security keys securely.
- Facilitates secure email communication.
- GPG (GNU Privacy Guard) is a GNU system's implementation of PGP.

### Key Exchange

#### Diffie-Hellman Key Exchange

- Developed by Whitfield Diffie and Martin Hellman.
- Allows two unrelated parties to jointly create a shared secret key over an unsecure communication channel.
  
#### DHE (Diffie-Hellman Ephemeral Key)

- Improved version of Diffie-Hellman.
- Provides perfect forward secrecy.
- Enhances security of the key exchange process.
  
#### ECDHE (Elliptic Curve Diffie-Hellman Ephemeral Key)

- An improvement upon Diffie-Hellman.
- Provides perfect forward secrecy.
- Ensures security of the key exchange process.

## Digital Certificate 

### Public CA

- Third-party entity issuing digital certificates for PKI.
- Useful when no existing trust relationship exists.
- Applications like Internet Explorer trust certificates from public CAs.
- Can revoke digital certificates in cases of fraud.

### Private CA

- Organization creates its own PKI.
- Self-signs digital certificates for asymmetrical encryption.
- Doesn't require payment for each certificate.
- Difficulty in acceptance of self-signed certificates by other organizations.

### Levels of Certificate Authorities

- PKI requires a hierarchical structure for CAs.
- Root CA issues certificates to subordinate CAs.
- Root CA self-signs its own certificate by default.

### Components of the Digital Certificate

- **Public key**: Encryption key of the entity.
- **Serial number**: Unique identifier of the certificate.
- **Algorithm**: Asymmetrical algorithm used.
- **Subject**: Entity issued the certificate.
- **Issuer**: Entity issuing the certificate.
- **Valid from**: Certificate start date.
- **Valid to**: Certificate end date.
- **Thumbprint algorithm**: Hash algorithm for certificate integrity.
- **Thumbprint**: Hashed value of the certificate for verification.

### Main Responsibilities of a Certificate Authority (CA)

- Issue digital certificates for PKI implementation.
- Review information provided in certificate signing requests (CSRs).
- Revoke digital certificates in cases of fraud or security breaches.
- Create, maintain, and publish a list of revoked certificates.
- Utilize methods like Certificate Revocation List (CRL) or Online Certificate Status Protocol (OCSP) for revocation.

### Recovery Agent

- Individual with authorized access to the private key archive.
- Used in PKI to protect against loss of private keys.
- Access to private key archive strictly limited.
- Recovery process often requires more than one agent.

### Registration

- Process used within organizations implementing PKI.
- Issue PKI certificates to employees or devices.
- Registration Authority (RA) verifies need for digital certificate.
- Passes request to Certificate Authority (CA) if required.












