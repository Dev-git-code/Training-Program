```embed
url: "https://www.youtube.com/watch?v=xmpYfyNmWbw"
```

# CompTIA Network+ Full Course

## Basic Network Theory and Terminology

- **Network** : an interconnected or interrelated chain, group, or system.
- **Computer Network**: Two or more computers are connected with one another for the purpose of communicating data electronically.
- **Components of a Network:**
  ![](https://i.imgur.com/ZKcmDKb.png)

- The **Adapter** acts as a translator between the components, the devices over the media by which the data is sent.
- **NODE:** Any device that is connected to a comms network.
  - Computers are called endpoint nodes
  - Routers/switch/hub are called redistribution nodes.
- **Server** : Provides resources and services like addressing 142.168.25.15
  - Manages devices on the network and controls network wide functions like permissions.
  - Server is a type of node.
- **Network backbone** : capable of communicating at very high speeds.
  ![](https://i.imgur.com/0jf2mvZ.png)

- **4 types of network backbone:**
  ![](https://i.imgur.com/IwTbxdB.png)

- **Terminal** : commonly called dummy computer.
  - No processing capabilities of its own
  - No memory of its own.
  - Terminal Emulator needed to emulate what's going on the server
- **Client** : The server which serves up the information, the client take the information and uses it.
  - has its own processor
  - has memory of its own
- **Peer**: It is both a server and a client.
  - provides its won resources and services
  - Self managed and Self contained
  - ![](https://i.imgur.com/2mTjzlz.png)
  - Peer - to - Peer communication

## Categories of Networks and Models

### LAN - Local Area Network

- Spans the area of a small building, or a floor of a larger building.
- Most commonly implemented technology is Ethernet.
- The Nodes in a LAN are directly connected to one another by cable or short range wireless
- Does not require a line to be leased from a service provider.

### WAN - Wide Area Network

- Spans a large area, and often multiple areas.
- Connects multiple local area Networks together.
- Utilizes Long Ranges Communications such as satellite or Radio Frequency.
- Can be Private or Public. The worlds largest Pubic WAN is the Internet.
- Types of WANs: PAN( Personal Area Network ) , CAN ( Campus Area Network ), MAN ( Metropolitan Area Network) , GAN ( Global Area Network ), EN ( Enterprise Network ).

### Intranet

- An organizations private version of the Internet.
- Keeps your network private, or secure from outside sources.
- uses same services and protocols as the Internet.

### Extranet

- A portion of your network that is opened to limited outside sources.
- Helps administrators maintain security to the rest of your network.
- Allows individuals like vendors to have minimal access.
- An extension of an entity's Intranet.

- **Segment:** A portion of a network with linked devices separated by a connectivity device such as a switch.

### Network Models

![](https://i.imgur.com/ZbNjCMm.png)

![](https://i.imgur.com/lKslfxs.png)

## Network Topologies

- **Topology:** describes the arrangement or layout of a comms network.
  - lines out the path data communication will take.
  - two types: physical and logical
- **Network Connections** : - **Point to Point**: A direct connection b/w two nodes of a network. - **Multipoint** : Nodes on a network are connected to two or more nodes simultaneously. Signals are not private. - **Radiated** : A wireless connection that is either Point to Point or Multipoint. Also considered a Broadcast connection.
  ![](https://i.imgur.com/kGMo65T.png)

![](https://i.imgur.com/GryXK0r.png)

![](https://i.imgur.com/G32qbIm.png)

![](https://i.imgur.com/KqD8Rog.png)

![](https://i.imgur.com/r8c3lai.png)

## Cables

- Cat 3 : Ethernet 10 Mbps, Voice traffic
- Cat 5 : Fast Ethernet 100 Mbps, 100 Mhz Frequency
- Cat 6 : Gigabit Ethernet 1Gbps Data rate, 200-250 Mhz

## Unbounded Network Media

- media that transmits wirelessly.
- DSSS ( Direct Sequence Spread Spectrum ) : uses multiple frequency channels
- FHSS ( Frequency Hopping Spread Spectrum )
- Bluetooth Transmission

### Wireless Access Point

- allows wireless devices to connect to the network
- **SSID** : Service Set Identifier ( name of your network )
  - 32-bit Alphanumeric string
  - Identifies your wireless access point

### Network Connectivity Devices

#### Network Interface Card

![](https://i.imgur.com/xc1z1jM.png)

#### Transceiver

![](https://i.imgur.com/8pfBMjO.png)

#### Switch

- Common connecting point for nodes on a network.
- looks at the MAC address of each packet of data for forwarding.
  ![](https://i.imgur.com/Kzj06kZ.png)

![](https://i.imgur.com/bH7VvWK.png)

#### Router

![](https://i.imgur.com/l4RSyCC.png)

#### Gateway

- similar to router in the way it functions
- allows networks with dissimilar protocols to communicate. ( through translation )
- Utilizes routable protocols similar to a router.
- not "default gateway" ( which forwards packets in TCP/IP).

### Virtualization

- **Virtual Switch :** Functions exactly as a Physical Switch. Cannot directly communicate between Virtual Switches. A router needs to be configured for this.
- **Virtual Router :** A virtual router is the software that can be installed on a device with two NICs for routing traffic.
- **Virtual Server :** A server that operates independently of its host machine. Software based CPU, RAM, NIC and hard drive.
- **Virtual Machines:** Similar to a virtual Server in that is own software based CPU, RAM, NIC, and hard drive. It is a software implementation of a machine to perform specific tasks and execute commands emulating a physical machine.
- **Virtual Desktop :** In windows systems a single desktop is the default that can be opened. It allows multiple desktops to be opened at the same time. Linux supports this with most distributions. Microsoft requires extra software installed (virtual pc) to allow default to be changed.

### Advanced Networking Devices

#### Multilayer switch

![](https://i.imgur.com/6sFQ8VD.png)

#### Wireless Controller

![](https://i.imgur.com/niSeOMm.png)

- WLCs permit mobile devices to roam ( Roaming means keeping same IP address and association )

#### Load Balancer

![](https://i.imgur.com/NUM6SC9.png)

#### IDS / IPS

![](https://i.imgur.com/SfoDJxu.png)

#### UTM

![](https://i.imgur.com/LJ8vIIo.png)

#### Next Gen Firewall (NGFW)

![](https://i.imgur.com/0ZHZwDi.png)

#### Content Filter

![](https://i.imgur.com/2HyK9Rx.png)

### Data Transmissions

#### Instantaneous Data Transfer

- Data is not stored in memory before it is transmitted.
- Eg: Online chat, video call
- Data is immediately converted to a network compatible format as it is being generated and transmitted.

#### Serial Data Transmission

![](https://i.imgur.com/1tSG8SS.png)
![](https://i.imgur.com/BD67l6A.png)

#### Parallel Data Transmission

![](https://i.imgur.com/K0aRopk.png)

#### Broadband Transmission

![](https://i.imgur.com/8ZmLppu.png)

### Media Access Methods

- There are rules that govern what node has access to transmit on the media at any given time.
- All nodes on the network will be configured to follow these rules.
- These rules ensure data delivery and data integrity is maintained.

#### Contention-based Media Access:

- Nodes compete with one another for media access time and utilization.
- Also called competitive, or collision based.
- Easy to implement and maintain, however data exchange can be delayed for nodes competing.

##### CSMA-CD (Carrier Sense Multiple Access Collision Detection)

- Contention Based media access method with a 5 step process used in Ethernet LANs.
- Attempts to provide collision free data transfer communications.
- Nodes transmit when they have data to send.
- When collisions occur they must be detected and managed.
  ![](https://i.imgur.com/jN3OKtn.png)

##### CSMA-CA ( Carrier Sense Multiple Access Collision Avoidance )

- Contention Based media access method with a six step process primarily used in wireless LANs.
- Attempts to provide collision free comms.
- Nodes transmit when they have data to send, but take steps before transmitting to avoid collisions.
  ![](https://i.imgur.com/VChq9Dm.png)

![](https://i.imgur.com/0NboXvZ.png)

#### Controlled Media Access

- Also called deterministic media access, has a device controls which nodes have access to the network media, and for how long.
- More difficult to implement and maintain as extra hardware and maintenance is needed.
- Ensures devices that have time sensitive data can transmit when needed, so are beneficial to time sensitive network.

##### Multiplexing

![](https://i.imgur.com/IiHat8J.png)
![](https://i.imgur.com/8affkFO.png)

- Both TDM and FDM rely on the central device called a multiplexer.
- A Mux - or Multiplexer, is the device that combines signals and transmits them to the receiving end where a De-Mux, or De-multiplexer separated the signals.

##### Polling

- A central device goes to each node in the network in turn to see whether the node has data to transmit.
- Guaranteed access as the process is repeated constantly.
- Not effective in time sensitive networks as time is potentially wasted in requesting from nodes that do not have data.
- A variation polling is Demand Priority.
- Each node signals its state of whether it has data to transmit or not.
- Contains priority measured and also safeguards to ensure nodes cannot constantly transmit.

### Signaling Methods

- **Signal :** Data translated into electromagnetic information that can be transmitted and received by communications devices.
- **Analog Signal :** A signal that carries data in a continuous stream or waveform via either electromagnetic, or optical energy.
- **Digital Data Transmission:** Digital data utilizes voltage diff. that represent the 1's and 0's. Two methods: a) On-Off keying; b) Manchester Encoding
- **Modulation:** Weaker, lower freq. signals are superimposed over stronger, higher freq. signals. Increases the range of transmission and decreases signal degradation.
- **Modem:** codec that translates digital to analog. DAC , ADC.
- Digital modulation is the translation of digital data into analog format for transmission over long distances.
- ![](https://i.imgur.com/iuY5wy8.png)
- ![](https://i.imgur.com/JgZWhGr.png)

## Common Ports and Protocols

### Ports

- process-specific or application-specific designation, serving as a comms endpoint in a computer's operating system.
- Identifies Processes and applications and the allowed communication paths they take in a network.
- Ports range from 1 to 65,535. Port 0 is reserved and cannot be used. - Well Known Ports : 1 - 1023 , used by well-known, common services. - Registered Ports: 1024 - 49151, reserved by applications and programs. - Dynamic/Private Ports: 49,152 - 65,535, used by unregistered services and temporary connections.
  ![](https://i.imgur.com/wiJxlA1.png)
  ![](https://i.imgur.com/7AO44Zq.png)

### File Transfer Protocol ( FTP )

![](https://i.imgur.com/8al7C7H.png)

### Simple Mail Transfer protocol

![](https://i.imgur.com/uuSBEuY.png)

### POP-3 Post Office Protocol

![](https://i.imgur.com/1JDoJVS.png)

### IMAP/4 : Internet Message Access Protocol

![](https://i.imgur.com/UnT6Vhc.png)

### NTP : Network Time Protocol

![](https://i.imgur.com/g2pJ4MO.png)

### NNTP : Network News Transfer Protocol

![](https://i.imgur.com/a6n6lmT.png)

### HTTP: Hyper Text Transfer Protocol

![](https://i.imgur.com/64HDCbp.png)

### HTTPS: Hyper Text Transfer Protocol over SSL (Secure Socket Layer)

![](https://i.imgur.com/h3rQNWr.png)

### Remote Desktop Protocol

![](https://i.imgur.com/nVAkt2h.png)

## Common Interoperability Services

- These services allow for computers to share resources securely and efficiently, even when they are completely different from one another.
  ![](https://i.imgur.com/VrDTqe6.png)

### NFS: Network File System

- App that allows users to access remote network files and resources.
- Used for systems that are dissimilar, such as Unix and Microsoft Systems.
- Functions independently of the Operating system, network architecture, or computer system it is installed on.
- Listens to port 2049 by default.

### Secure Shell

- A very secure method to access a computer and resources remotely.
- Creates a secure session, or shell with the remote machine by using authentication mechanisms.
- `SSH1 != SSH2`
- SSH2 contains SFTP ( Secure File Transfer Protocol )
- port 22 by default

### SCP: Secure Copy

- Secure Copy : A secure method of copying files from one device to another remotely.
- Works with many systems including Unix, Microsoft, Linux and Mac.
- Also uses port 22 by default

### Telnet ( Tele Comms Network )

![](https://i.imgur.com/A5oItDp.png)

### SMB: Server Message Block

- also know as CIFS ( Common Internet File System )
- used for providing communication to nodes on a network, access to files and peripheral devices and ports.
- Most well known for accessing file systems or printers on shared networks or from the server
- Port 445 by default.

### LDAP: Lightweight Directory Access Protocol

- main purpose is for accessing and maintaining distributed directory information services, in an IP network.
- deals with users / permissions
- used for managing directory information and tasking in networks that contain user, object or other kinds of directories.
- Port 389 by default.

### Zeroconf : Zero Configuration

![](https://i.imgur.com/5Qx9cqY.png)

## Network Infrastructure and Design

### The OSI model

![](https://i.imgur.com/i42hFpV.png)
![](https://i.imgur.com/DlRjtGJ.png)
![](https://i.imgur.com/OU6YJGC.png)
![](https://i.imgur.com/rKyM4tu.png)
![](https://i.imgur.com/I1nTLlo.png)
![](https://i.imgur.com/ex3suoZ.png)
![](https://i.imgur.com/WT87x53.png)
![](https://i.imgur.com/dBVMekc.png)

### The TCP/IP model

![](https://i.imgur.com/q0gZfoa.png)
![](https://i.imgur.com/1XH4fGj.png)
![](https://i.imgur.com/kvaRhfQ.png)
![](https://i.imgur.com/WxNX7q9.png)
![](https://i.imgur.com/tpJZaZQ.png)
![](https://i.imgur.com/10SJ34B.png)
![](https://i.imgur.com/tysjjcv.png)
![](https://i.imgur.com/MbIUo0G.png)
![](https://i.imgur.com/uibPpx0.png)
![](https://i.imgur.com/Py672IO.png)
![](https://i.imgur.com/aFD7txt.png)

#### Protocol Binding

![](https://i.imgur.com/C1IvZip.png)

## WLAN

![](https://i.imgur.com/RcnDhZg.png)

![](https://i.imgur.com/0FCJm7W.png)
![](https://i.imgur.com/VkBM42k.png)
![](https://i.imgur.com/OPqdE8R.png)

## IEEE 802.11

- CSMA/CD
  ![](https://i.imgur.com/vuvzLDu.png)

![](https://i.imgur.com/bngd17o.png)

![](https://i.imgur.com/wHAmIqz.png)

## Network Segmentation

- enhances the security of a network
- isolate critical infra to prevent unauthorized access
- used for reducing network congestion
  - A single department may have more network traffic than others.
  - We can segment the network by department to limit the traffic to each individual segment.
  - By restricting the traffic, we can increase the available bandwidth of the network
- also useful for load balancing purposes.
- Network segmentation is done for PCI (Payment Card Industry) compliance:
  - To ensure that the payment transactions are done in a secure environment.
  - It is done to isolate the network that stores, processes, or transmits cardholder information from the rest of the network.
- The footprint of sensitive information is confined to a network segment:
  - Its boundary that comes into contact with the public or untrusted network can be protected using the following for PCI compliance:
    - Firewall
    - Intrusion detection systems

## Network Routing and IP Addressing

- **TCP( Transmission Control Protocol ):** Connection oriented, guaranteed delivery, with reliability features that include:
  - Flow control (reduces overloading)
  - Checksum mechanism (minor)
  - Limits maximum segment size (prevents MTU/MUT mismatch)
  - For applications that depend on reliable data delivery
- **IP(Internet Protocol)** : Connectionless, best effort delivery. Outlines:
  - Information structure (datagrams)
  - Navigation and route establishment
  - Specifications to connect to the Internet
- **UDP ( User Datagram Protocol )** : Connectionless protocol for those applications that require expedience over reliability features:
  - Best effort delivery.
  - Stateless protocol prefers packet loss over delay in retransmitting.
  - Checksum for data integrity. • Addresses port numbers for functions: (DNS:53)
  - VoIP or on-line gaming.
- **ARP ( Address Resolution Protocol ) & RARP ( Reverse ARP )** :
  - ARP: Request and reply protocol that:
    - Maps IP addresses to MAC addresses
    - ARP Process:
      1.Receives IP address from IP
      2.Looks in ARP Tables for mapping
      2a. If there: 3. MAC returned to IP
      2b. If not: 3. Broadcast message sent 4. Target responds (Unicast), 5. MAC Added to table 6. MAC returned to IP
- **ICMP ( Internet Control Message Protocol ):**
  - attempts to report on system status.
  - used for diagnostic and testing purposes.
  - Utilities from ICMP: Tracert, Pathping, Ping
  - Internet Layer Protocol
  - Ping uses ICMP echo requestes.
- **IGMP ( Internet Group Management )**:
  - used to establish memberships for multicast groups.
  - can be used fro one-to-many comms.
  - ![](https://i.imgur.com/CN9DFwg.png)

### IP packet Delivery Process

![](https://i.imgur.com/tO28avD.png)

## IP addressing and Subnetting

![](https://i.imgur.com/zYr9W9U.png)

![](https://i.imgur.com/7ktpv4w.png)

![](https://i.imgur.com/sJ1x29K.png)

![](https://i.imgur.com/aUSxJj5.png)

![](https://i.imgur.com/fiau6kJ.png)

### IPv4 Addressing

![](https://i.imgur.com/CmqOXu5.png)

![](https://i.imgur.com/hB3t0oE.png)

![](https://i.imgur.com/xrP7Jh9.png)

![](https://i.imgur.com/r4a8SwL.png)

![](https://i.imgur.com/RVKKVVa.png)
 the default gateway is a *device, such as a DSL router or cable router, that connects the local network to the Internet*.

#### Classless Inter Domain Routing

![](https://i.imgur.com/F3dxQ0q.png)

### IPv6

![](https://i.imgur.com/bgeBcgW.png)

![](https://i.imgur.com/mMG849Y.png)

![](https://i.imgur.com/q9PTplW.png)

![](https://i.imgur.com/acbSIZw.png)

![](https://i.imgur.com/kTY3lBO.png)

![](https://i.imgur.com/fC8zAN8.png)

![](https://i.imgur.com/oByKW9i.png)

## IP Assigning and Addressing Methods

- Dynamic addressing uses DHCP ( Dynamic Host Configuration Protocol )

### DHCP

![](https://i.imgur.com/giWsy5l.png)

- Even when using DHCP, some network systems still use static addresses
  - The DHCP server itself changing
  - Domain Name Service (DNS)
  - Web server
  - Printers/Servers - Routers/Gateway

## DNS ( Domain Name System )

- A domain name is the name of a comp that has an IP address on the Internet.
- A single IP address can have many domain names associated with it.
- DNS resolves a domain name associated with a server to its IP address.
- **Domain Name System (DNS) Database**
  - DNS knows about the relationship between a domain name and its IP address.
  - DNS is a distributed database that is spread across the world.
  - DNS Uses UDP port 53
  - TCP used for zone transfers or large requests
- DNS Root Servers : Contain the IP addresses of Top Level Domain (TLD) registry organizations that maintain global domains and the country code domains
- DNS is compose of:
  - Namespace: The distributed database containing data that includes host names and domain name. These name form a hierarchical tree structure similar to file system in UNIX.
  - Name Server: Server that translates a domain name into its corresponding IP address. It does this translation in response to the DNS query it receives from resolvers or other name servers.
  - Resolver : The resolver accepts the DNS queries, and if the required information is available in the local cache, then it returns that data to the client
- DNS Records : Records contained in a name server database that have the resource information associated with a DNS domain.
- A Records: Also called address records. map a domain to its IPv4 address.
- AAAA Records : maps a domain to its IPv6 address.
- Dynamic DNS: The process of automatically updating a dynamic DNS record in the name server. Dynamic DNS is especially useful when IP addresses of our devices keep changing because of DHCP decimal numbers

## Proxy Server

- A proxy server is a server that functions as a mediator between the following:
  - A client computer
  - Destination servers on the Internet.
- ![](https://i.imgur.com/kb0jLR8.png)
- A proxy server does the following:
  - Makes requests on behalf of the client computer
  - Receives the response from the server on the Internet
- used to increase the performance and security.
- Proxy servers increase performance by caching web content:
  - When a client computer requests a web page stored in proxy server's cache, the proxy server provides that web page, which is faster than getting it from Internet.
- Proxy servers increase security:
  - They can filter out unwanted web content and malicious files before sending out the information to the client computer.
  - When a client computer unknowingly tries to download a malicious file, the proxy server can filter out the file before it can reach the client computer.
- Forward Proxy Server
  - A forward proxy server does the following:
    - Acts on behalf of a client computer
    - Gets the requested information from different servers.
  - These servers on the Internet only interact with the proxy server, they do not know about the client's existence.
- Reverse Proxy Server
  - ![](https://i.imgur.com/rGPnFc1.png)
  - This is a scenario where a client on the Internet wants to access information from servers inside an organization. The client is not aware of the servers' existence. It treats the proxy servers as the origin server.
  - A reverse proxy can be used to balance the load on a server farm.
  - They intercept all the traffic coming from the Internet.
  - They make it difficult for the hackers to get the details of the internal network.

## Network Address Translation

- Translating private IPv4 addresses into public IPv4 addresses that are routable on the Internet.
- It is at the boundary where the local area Network interfaces with the internet.
- implemented by deploying NAT-enabled router.
- We can hide the internal IP addresses of our private network from the public network (Internet).
  ![](https://i.imgur.com/unCXiN8.png)
  ![](https://i.imgur.com/xQyrMyX.png)

## Port Address Translation

![](https://i.imgur.com/icTIjdO.png)

- specific function of NAT.
- It allows mapping of may private IPv4 addresses to a single IPv4 public address but using different ports.

## TCP/IP Simple Services

![](https://i.imgur.com/gWz9Q9h.png)

## TCP/IP Tools and Commands

### Ping

- tests connectivity end-to-end
- can also test maximum transmission unit
- ![](https://i.imgur.com/f2mVrkY.png)

### Traceroute

- tests where connectivity may have been lost
- Checks time of end-to-end connection
- ![](https://i.imgur.com/ueDpGeK.png)

### Protocol analyzer/ network analyzer

- gives a readable content list of packets
- captures packets into a buffer ( based on a filter )
- ![](https://i.imgur.com/pceTPar.png)

### Port Scanner

- Scans for open ports
- ![](https://i.imgur.com/wgAGnAP.png)

### Nslookup/DIG

- provides server and domain information about any queried address.
- ![](https://i.imgur.com/yNfqwdK.png)

### Address Resolution Protocol

- Resolves IP addresses to MAC addresses.
- ![](https://i.imgur.com/GnexHOF.png)

### Route

- Displays routing table
- Gives ability to edit table

## LAN

### Switching

- Switch - an Ethernet connectivity point.
- connects devices via cable.
- ![](https://i.imgur.com/GSkXYAX.png)
- Multilayer switch:
  - Functions as both a router and switch.
  - can deal with both MAC and IP addresses.
  - ![](https://i.imgur.com/p6FRZJ0.png)
- content switch
  - Receives data and determines where it should go
  - ![](https://i.imgur.com/ApScwFS.png)

### STP ( Spanning Tree Protocol )

- allows switches to communicate in order to prevent loops.
- algorithm runs to find and block possible causes of loops.
- loops occur when there is more than one path for a frame to take.
- based on two key components
  - Bridge ID
  - ![](https://i.imgur.com/XJ489Ki.png)
  - Path Cost
  - ![](https://i.imgur.com/O41CcCx.png)
- STP Four Step Path Selection Process
  1.  Lowest Root BID
  2.  Lowest Path cost to Root Bridge
  3.  Lowest Sender BID
  4.  Lowest Port ID
  - All happens after the exchange of Bridge Protocol Data Units (BPDUs)
- Initial STP Convergence Process
  1.  Root Bridge election
  2.  Root Ports election
  3.  Designated Ports election
  - Bridge with lowest BID selected as root
- Root Port Election
  - Root port is the port closest to the root bridge
  - Every bridge except the root bridge must elect root ports
  - Each interface adds cost to BPDU as it travels across it
  - Fa0/1 19 and Fa0/2 = 38 so Fa0/1 wins
- ![](https://i.imgur.com/UiFpn7U.png)
- Designated Port Election
  - Sends and receives traffic on the segment to the root bridge
  - Only one designated port per segment
  - Tie goes to lowest Root BID - Lowest Root Path Cost - Lowest Sender BID- Lowest Port ID

### Routing

- Connects data from one network to another
- Routes the paths that the data takes
- ![](https://i.imgur.com/wOl8sUE.png)

#### Terms

- Hop counts - number of hops to reach a connection
- Costs - the number of links/hops in a route. Lower cost routes are favored.
- Latency - time it takes a packet to travel between locations
- Convergence - when the network changes, the routers have to discover it.

#### Routing metrics

- The routing table of a router contains a field called a metric.
- A metric is a value allocated to a router:
- It is used by a router to choose the best router when it is confronted with more than one route to get to a network.
- If a router has different routes to the same network the routing metric helps the router decide which one to choose.
- The routing protocols will choose a route with the lowest metric.
- Router metrics can be based on factors, such as the following:
  - Maximum Transmission Unit
  - Costs
  - Latency
  - Administrative distance
  - Shortest path bridging
- EIGRP routing uses characteristics such as Delay, Bandwidth, Reliability, Load to calculate the best path selection.

#### Routing tables

- Routers have a database of routes stored in a table called a routing table.
- Routers use the information in the routing tables to make a decision about the next hop where it has to forward the traffic.
- A routing table contains the following:
  - Network ID: The destination network address and subnet mask.
  - Next hop/Gateway: The address of the next router to which the packet will be sent to get to the destination network.
- The routing information in the routing table is populated through three different means: - A static route ( route manually added by admin ) - A dynamic routing protocol : - A routing protocol that dynamically builds routing information such as the Network, Next hop , Topology in a routing table. - A physically connected network
  ![](https://i.imgur.com/4VTIr8J.png)

### Dynamic Routing

- Routers learn from other routers
  - Build table based on communication
  - Two Kinds of Protocols
    - Distance - Vector Protocols
    - Link-State protocols

#### Distance - Vector

- Routers using this only share route information with the routers they are attached to
- Convergence is longer with Distance-Vector than Link- State
- Protocols:
  - Routing Information Protocol (RIP)
  - Routing Information Protocol version 2 (RIPv2)
  - Border Gateway Protocol (BGP)
  - Enhanced Interior Gateway Routing Protocol (EIGRP)

#### Link-State

- Routers using this know of all routers on network
- If change occurs, they automatically update
  - Quicker convergence
- Protocols
  - Open Shortest Path First (OSPF) -- medium networks
  - Intermediate System-to-Intermediate System (IS-IS) -- larger networks

### IGP and EGP

- Dynamic routing protocols can be classified into the following:
  - Interior gateway protocols
  - Exterior gateway protocols
- An Autonomous System is one or more networks that are governed by a single administration.
- In an autonomous system, administration of the entire network is under the control of a single authority
- ![](https://i.imgur.com/JZ1Wt5g.png)
- IGP is used to route packets within AS and EGP to route packets between AS.
- Common IGP - RIP, OSPF, IS-IS, EIGRP
- Common EGP is Border Gateway Protocol, used for inter-AS routing. BGP uses TCP and listens on TCP port 179.

### Routing Loop

- packet gets routed b/w two or more routers endlessly.
- if routing table entries are incorrect, then a routing loop can occur.
- Routing loop increases packet loss, increase link utilization, increases CPU utilization
- In distance vector routing, slow convergence causes routing loop. Solution:
  - Split horizon
  - Poison reverse

### VLANs and SOHOs

- VLAN - group of computers that act as if they are on their own network, but are not
- Similar functioning computers are segmented together virtually.
- Advantages: - Security - Performance - Organization - Administration
  ![](https://i.imgur.com/fsQDysF.png)

- VLAN membership can be assigned using different methods:
  - Protocol- based VLANs
  - Port-based VLANs
  - MAC address-based VLANs
- Trunk Ports : A special port type, carries data from multiple VLANs
- SOHO : Small Office, Home Office - generally server 1-10 users.

## WAN ( Wide Area Networks )

- Implementing WAN :
  - Set up VPN ( Virtual Private Network )
  - Give access to users
  - Connect users to network
- WAN admin needs to manage backups, monitor security.
- WAN transmission technologies: ISDN, T-Carrier, SONET, X.25 and Frame Relay, ATM
- MPLS ( Multiprotocol Label Switching ): Technology that provides WAN connectivity b/w two geographically distant offices.
- GSM - (Global System for Mobile Comms) , LTE ( Long term Evolution) , WiMAX ( Worldwide Interoperability of Microwave Access )
- Uses packet switching ( like torrent )
- VoIP is a way to make calls using IP packets
  - Calls can also be made via the Internet
  - No additional cost to use
  - SIP-Session INITIATION PROTOCOL

## Remote Networking

- accessing a network without being physically present on the site of the server.
- ![](https://i.imgur.com/dX0t0PL.png)

### Terms

- VPN - virtual private network ( tunneling )
- RADIUS ( Remote Authentication dial-in User Service ) - provides authorization, authentication, and accounting management when using remote networking.
- TACAS+ - provides validation of users that are trying to remotely connect to a network.

### Remote Access and Implementation

- very convenient way of connecting to a network.
- provides a connection that can greatly reduce costs ( flexibility )

#### Remote Access Methods

##### Remote Desktop Protocol

- Microsoft proprietary
- Allows remote access and control via screen sharing
- TCP port 3389
- Client can be Windows, Mac, Linux etc.

##### Secure Shell (SSH)

- Remote terminal access
- Encrypts communication between endpoints
- SSH must be enabled on server/router/switch
- Client software used e.g. Putty

##### Virtual Network Computing

- Platform independent Graphical desktop sharing system GUI
- Uses Remote Frame Buffer to remote control computer
- TCP port 5900+ N (display number e.g. O for physical display)

##### Remote File Access

- FTP up/download large files insecurely (credentials) port 21
- SFTP-secures/encrypts traffic (uses SSH 22) 31
- Security issue if enabled by default
- TFTP - transfers small files insecurely (UDP 69)

### VPNs and Protocols

- VPN extends Lan, or can connect two LANs
- is used to set up a WAN
- A type of remote access ( uses internet )
  ![](https://i.imgur.com/s6IeTS8.png)
- Components Needed:
  - VPN client
    - software ( built into OS )
    - Hardware ( built into route or separate device ( VPN concentrator ))
  - VPN Server
  - Access Methods ( Intranet or Internet )
  - VPN Protocols
    - PPTP - Point - to - Point Tunneling protocol
    - L2TP - Layer 2 Tunneling Protocol ( generally used )

### GRE ( Generic Routing Protocol )

- tunneling protocol developed by Cisco.
- primary benefit of tunneling is : we can run a protocol over a network that doesn't support that protocol.
- GRE creates virtual point-to-point links that encapsulate a variety of network layer protocols over an Internet Protocol network.
- ![](https://i.imgur.com/ZrUy2rn.png)

### Secure Sockets Layer VPN (SSL VPN)

- In SSL VPNs, users connect to VPN devices using their web browsers.
- The traffic between the web browser and the VPN device is encrypted with the SSL protocol.
- SSL VPNs provide common security services, Authentication ,Encryption ,Integrity protection, Access control, Endpoint security controls, Intrusion prevention

### VPN concentrator

- VPN provides a remote user with secure access to the organization's resources.
- The VPN tunnel or connection that a user is accessing terminates at the VPN Concentrator located in the user's organization.
- It can handle multiple VPN tunnels
- provide VPN encryption by using IPsec or SSL for web-based applications
- IPsec:

  - provides high level of security and encryption
  - requires client software to establish VPN tunnel.
  - better for fixed locations
  - SSL is better for remote users that connect from various locations.

- Caching Engines
  - uses proxy servers
  - engines copy web pages and store them for when other users request them
  - saves bandwidth

## Network Security

- Secure VPN
  - require remote users to use multiple identification methods
  - have a firewall separate VPN from the network.
- Managing users Access privileges ( principle of least privilege )
- Clean up inactive accounts

### AAA

- Authentication
  - verifies the identity of a user trying to access the network
  - usually comes in the form of username and password recognition
- Authorization
  - Determines what each user can access
  - Tells what programs, services, and data a user has access to
- Accounting ( Auditing )
  - measures a user's activity and resource consumption while using the network

### System Security Tools

#### Firewall

- a security system that analyzes packets of data and determines if they should be allowed into or out of the network
- uses port scanner to allow specific inbound or outbound ports
- can be software ( built into OS ) or Hardware ( SOHO router )
- keeps data secure, help prevent identity theft

### IDS/IPS implementation

#### Intrusion Detection System (IDS)

- used to detect attack on a network and report them - Behavior based - Signature based ( historical or known pattern )
  ![](https://i.imgur.com/Qk9GyJu.png)

#### Intrusion Prevention System ( IPS )

- detects attacks and prevents them from happening
  ![](https://i.imgur.com/1n88Qi1.png)

#### Implementing

- find ideal place
- tune the alerts to be effective
- establish someone/a way to constantly monitor
- establish procedures

### IPSec and IPSec Policies

- IPSec helps provide security and safe communication between systems, both local and wide.
- uses two main Protocols
  - Authentication Header ( AH )
  - Encapsulating Security Payload ( ESP )
- IPSec provides these main services:
  - Data verification
  - Protection from data tampering
  - Private transactions
- IPSec Policies
  - Policy elements
    - Filters
    - Network Info

### Denial of Service ( DoS )

- refers to an attack on a network to make its service and resources unavailable to the legitimate users.
- floods the network with useless traffic.
- When the attacker burdens the server with too many requests, the web server is unable to process or respond to legitimate request.
- As a result, we can't access that website, and that it is called a Denial of Service attack
- Common types : Buffer overflow attacks, SYN attack, Teardrop attack, Viruses
- Buffer overflow attacks
  - Distribute e-mails including 256 character file names
  - Send huge Internet Control Message Protocol (ICMP) packets
  - Send a lengthy e-mail message including a "From" statement that has more characters than 256.
- SYN Attacks

  - The attacker sends TCP connection requests faster than the targeted computer's processing speed.
  - Using client-server technology, it establishes a TCP three-way handshake.
  - The attacker sends repetitive SYN packets to every port on the particular server using a fake IP address.
  - The server, ignorant of the attack, establishes the communication by responding to all the requests.
  - It replies to each attempt with an SYN-ACK packet from every open port.

  - ![](https://i.imgur.com/g2luA53.png)

- DDoS : the computer uses multiple host computers to launch the attack.

### Common Networking Attacks

- Social Engineering: An attacker convinces an employee to disclose confidential information. The attacker may trick the employee into thinking they are a legitimate source, such as a tech support person.
- Insider Threats: An employee or contractor with authorized access to the network uses that access to harm the network.
- Logic Bomb: A malicious code that is set to detonate at a specific time or when a certain condition is met.
- Rogue Access Point: A fake wireless access point set up by an attacker to intercept data from unsuspecting users.
- Wireless Evil Twin: A Wi-Fi network that appears legitimate but is actually a malicious network set up by an attacker to steal data from users. Mitigate with HTTPS or VPN tunnels.
- War Driving: The act of driving around with a laptop or other device looking for unsecured wireless networks.
- Phishing: An email or message that appears to be from a legitimate source, such as a bank or credit card company, but is actually from an attacker trying to steal personal information.
- DNS Poisoning: An attacker redirects traffic from a legitimate website to a malicious website.
- ARP Poisoning: An attacker tricks a computer into associating a fake Media Access Control (MAC) address with a legitimate IP address. Combat with dynamic ARP inspection and DHCP snooping.
- Spoofing: An attacker makes a computer or server appear to be something it is not.
- De-authentication: An attacker disconnects a legitimate user from a network.
- Brute Force Attack: An attacker tries to guess a password by trying a large number of possible combinations.
- VLAN Hopping: An attacker gains unauthorized access to a virtual LAN (VLAN). Done via Switch Spoofing or Double-tagging.
- Man in the Middle Attack: An attacker intercepts communication between two devices and can eavesdrop on the conversation or modify the data being sent. Accomplished using DNS or ARP spoofing.
- **Vulnerability Scanning:**
  - Probing a host in order to find an exploitable service or process
  - Plethora of tools available to find exploits
  - Tells the hacker what type of attack would work best
  - Prevent by doing your own penetration testing
  - Nmap freely available to use for testing
- **Threat Mitigation:**
  - Implement strong security policies: This includes password policy, download policy, and internet use policy.
  - Monitor threats: This includes monitoring internal threats and researching external threats.
  - Educate users: Teach users about social engineering and how to avoid falling victim to it.
  - Automate scanning and updates: Automate virus scans and software updates to reduce the risk of attacks.
  - Patch systems regularly: Apply security patches to systems as soon as they become available to fix vulnerabilities.

### Advance Threat Management

- **Signature Management**

  - Primary method used by IDS/IPS
  - Signature-based detection examines network traffic for preconfigured and predetermined attack patterns
  - These are known as signatures Attacker convinces employee to disclose confidential information
  - If a known signature is identified by the system, an alarm will be triggered or the traffic will be blocked
  - Signature codes must be updated for new/false patterns

- **Change Native VLAN**

  - Native VLAN used for any untagged traffic
  - Big security vulnerability
  - Native VLAN passes CDP, DTP Unused 222 Accounting VLAN 20
  - All ports on switch in VLAN1 by default

- **DHCP Snooping**

  - Protects against rogue DHCP servers on the LAN
  - Forces switch to examine/filter inappropriate DHCP messages
  - Uses trusted / untrusted ports

- **VLANs**

  - separate hosts into functions
  - Broadcasts limited VLAN hosts

- **Access Lists**

  - can block network, hosts, ports and protocols
  - List of permitted or denied traffic

- **Honeypot / Honeynet**
  - Honeypots attracts possible attackers into an isolated environment
  - They can't do any harm in this place
  - You analyze their behavior and gather information
  - Honeynets are a chain of honeypots
  - Usually placed in network segments isolated by firewalls

### Secure the Wireless Network

#### WiFi Protected Access (WPA)

- WPA available from 2003 - dynamic key management (built on EAP)
- WPA uses Temporal Key Integrity Protocol (TKIP) 500 trillion key combinations
- Used with RADIUS in the enterprise
- Uses and encrypted hash

#### WPA2

- Based on 802.11i architecture
- Allows users/devices to authenticate with EAP plus TACACS+/RADIUS
- RC4 replaced by AES (Advanced Encryption Standard) 256 bit and beyond
- TKIP replaced by Computer Mode with Cipher Block Chaining (CCMP)
- Uses and encrypted hash

#### MAC Address Filtering

- Access granted / denied based upon MAC address
- Should be used with other security in case of MAC spoofing

#### Extensible Authentication Protocol - (EAP)

- Authentication framework used in wireless networks (RFC 3748)
- EAP MD5 - uses a series of challenges and responses
- EAP TLS - designed by Microsoft. Uses certificates
- EAP FAST - designed by Cisco. Uses a secure TLS tunnel with SSL
- EAP-FAST - uses shared secret keys (unique to each user/protected access credentials)

## Hardware testing

- Diagnostic software
  - Runs a series of tests on a system's hardware in the event of issues
  - The test produces a list of possible hardware elements that may be malfunctioning
- POST cards
  - POST-power-on self-test code beep code
  - Used to troubleshoot computers that are not starting up

## Software testing tools

- Packet sniffer
  - valuable troubleshooting tool
  - sends a copy of the frame to a device
  - can check traffic patterns, baseline, irregularities
  - mirrors a port you want to monitor
  - often used by hackers ( so use SSH )
- Wi-Fi Analyzer
  - Reports on SSID, MAC addresses, Channels used, speeds
  - Can represent outputs in graphical form
  - Tells you security protocols in use (or lack of)
- Bandwidth Speed Tester
  - Also known as throughput testers Can be hardware or software based
  - Injects traffic into the network and provides results
  - Can represent outputs in graphical form
  - Free to download or paid
- Command Line Tools
  - ipconfig (windows) - ifconfig ( linux )
  - IP information for local interfaces
  - Can use switches to drill down e.g. ipconfig/all
- iptables
  - unix command
  - configures kernel firewall
- netstat
  - Network statistics
  - Shows your active connections
  - Tells you the type of services you are running .
  - netstat -a: lists all active connections (see the screenshot below)
  - netstat -b: Visits the applications (executables) that use the active connections .
  - netstat -n; lists the connections without doing a DNS resolution
- tcpdump
  - Unix command
  - Sniffing tool ( Snoop command in Solaris)
  - Enables view of packets on the wire
- pathping
  - TCP/IP tool
  - Provides information about network latency
  - Sends ICMP echo requests
- nmap
  - used to discover computers and services on a computer network in order to create a map of the network.
  - Vulnerability scanning tool
  - used for auditing ( or by hackers )
- dig
  - Domain information gropher
  - Queries DNS servers
  - same as nslookup tool ( used in linux )
  - Tells you IP address, DNS servers, cache timers

### High Availability - VRRP and HSRP

- Protocols like Virtual Router Redundancy Protocol (VRRP) and Hot Standby Router Protocol (HSRP) provide high availability for a default gateway
- VRRP and HSRP enable multiple routers to act as a virtual router with a virtual IP address
  ![](https://i.imgur.com/YTJIhhR.png)

### Load Balancing

- Load balancing refers to the distribution of work load across multiple computing resources, such as servers and networks.
- If we have a server overloaded with requests, then we can have several servers share the burden of that single server.
- With load balancing, we can have multiple servers act as a single server.
- benefits of load balancing: Resource optimization, Maximum throughput, Efficiency, High Availability

## SNMP ( Simple Network Management Protocol )

- SNMP is an application-layer protocol meant for exchanging management data between the devices on a network
- SNMP is specifically used to monitor and manage devices on the network, such as routers, switches, servers, storage array....
- consists of : - Managed device : device on the server that requires some kind of monitoring and management. eg : storage array - SNMP agent : program that runs on the managed device - SNMP manager : computer that runs Network Management System and communicates with the SNMP agent.
  ![](https://i.imgur.com/yD7Cuwa.png)

- Management information Base, or MIB, is a database maintained by SNMP agent.
- It contains info about the managed device, shared by both SNMP agent and SNMP manager.
- SNMP working :
  - SNMP is typically enabled in a storage system
  - Whenever a specific event occurs in the storage system, the SNMP agent running on it will notify the SNMP manager by sending a message
  - Since this message is said to trap an event, it is called an SNMP trap
  - When the SNMP manager receives the event, it takes an action depending on the event
  - In email and SMS alerting methods, when an event for which we had configured the alert occurs, the device will send out an email or SMS to the designated users
- The SNMP agent receives requests on UDP port 161. The manager may send requests from any available source port to port 161 in the agent. The agent response will be sent back to the source port on the manager. The manager receives notifications (Traps and Inform Requests) on port 162

## Syslog

- A protocol for exchanging log messages
- Can be used by the devices on the network to move audit logs to a central logging server, called a Syslog server
- allows consolidation of audit logs from multiple devices into a single place.

## SIEM

- SIEM stands for Security Information and Event Management (SIEM)
- Refers to software products and services that are used to monitor a network
- Provides real-time analysis of security alerts generated by network hardware and applications
- SIEM is a combination of Security Event Management (SEM) and Security Information Management (SIM)
- Security Event Management deals with the real-time monitoring and notifications of security events.
- Security Information Management deals with the collection of log files into a central repository for review and analysis
- SIEM solutions are used to log security data and generate compliance reports.

## Unified Communications

- describes integration of voice, video, and data comms in an IP network.
- simplifies the real-time enterprise communication possible, such as Making calls, Instant messaging, Video and audio conferencing, Desktop sharing.
- allows users to send messages on one medium but receive the response through another medium. For example, a voicemail can be received, but it can be accessed through email
- Allows users to check and retrieve emails or voicemails using any communication device at any time
- allows users to communicate seamlessly even if they are in different locations.

## Virtualization

- Virtualization refers to the technologies that allow a single physical computer environment to operate as multiple virtual machines simultaneously, by transforming the physical hardware resources of a computer into virtual hardware resources.
- A virtual machine is an isolated software replica of the original computer complete with all processor instructions and system resources.
- VM are completely separate and independent.
- The virtualization software transforms the hardware resources of a computer, including the CPU, memory, storage, and network adapter, into virtual hardware resources that are shared among multiple virtual machines.
- The virtualization software provides a layer of abstraction between the virtual machines and the underlying physical hardware.

## Virtual Networking

- A virtual network is a system in which two or more virtual machines are connected logically to each other, So that they can send and receive data from each other.
- Each vNIC has its own MAC address just like the physical NICs or PNICs.
- A virtual switch can send network traffic Between the virtual machines on the same host Or From the virtual machines to an external network that is outside the virtualized host.

### Software Defined Networking

- Software-Defined Networking, or SDN, provides a high-level administration capability to the network administrators.
- It allows them to manage a network through a user interface that abstracts the complexity of the underlying networks.
- used to control the operation of network devices, such as routers and switches.

## Storage Area Network

- A Storage Area Network is a high-speed network
- It allows data transfer between the computer systems and the storage devices, as well as among the storage devices.
- SAN offers low latency for the I/O requests to access the storage device.
- allows several servers to connect to several storage devices in order to share data.
- also allows storage devices to communicate with each other.
- SAN is scalable as it allows many new storage devices to be added without adding new servers.
- ![](https://i.imgur.com/SA06Zmc.png)
  ![](https://i.imgur.com/B7MkEid.png)
- Jumbo Frame: Ethernet frame that has a payload greater than 1500 bytes, and it can carry a payload of up to 9000 bytes.

## Cloud Computing

- A Cloud computing is a model for enabling ubiquitous, convenient, on- demand network access to a shared pool of configurable computing resources (e.g., networks, servers, storage, applications, and services) that can be rapidly provisioned and released with minimal management effort or service provider interaction.
- Characteristics:
  - On-demand self-service
  - Broad network access
  - Resource pooling
  - Rapid elasticity
  - Measured service
- Three service models
  - Software as a Service ( SaaS )
  - Platform as a Service ( PaaS )
  - Infrastructure as a Service ( IaaS ):
    - Private cloud
    - Community cloud
    - Public cloud
    - Hybrid cloud

## Common Network Issues

- Incorrect Default Gateway
  - User experience no connectivity
  - The IP address assigned to a default gateway may be incorrect
  - Changing the IP address to the correct IP address will resolve the problem
- Broadcast Storms
  - Users may experience degradation in network performance
  - Broadcast storm refers to a situation where a network is flooded with broadcast traffic
  - Switching loop may be the cause of broadcast storm
  - Configuring STP on switches will help solve the problem
- Duplicate IP
  - User may get a "conflicting/duplicate IP address" error message preventing network communication
  - Occurs if two or more hosts were configured with the same IP address
  - To avoid this issue, change the IP addresses of the affected host(s) to have unique IP addresses
- Speed and Duplex Mismatch
  - User may experience slow network performance
  - \The communicating devices may have different port speeds and duplex settings
  - Common cause is when auto-negotiation is enabled on one side of the link and disabled on the other side
  - It is reliable to manually configure network speed and duplex settings for servers and the other critical links
- Incorrect VLAN Assignment
  - User may experience no connectivity or may not be able to access specific computing resources
  - Network devices may be assigned to different VLANs
  - Configuring the devices to correct VLANs will solve the problem
- Misconfigured DHCP
  - Some users or all users may experience no connectivity
  - DHCP pool doesn't have sufficient IP addresses to cover all devices or is not assigning correct IP addresses
  - To avoid this issue, ensure DHCP has the right configuration and the DHCP server has sufficient IP addresses for all the devices
- Misconfigured DNS
  - Users may experience no internet connection or may not be able to access computing resources using device names
  - \A host may be configured with the wrong DNS server information, and so the name resolution will not happen
  - To avoid this issue, ensure that the host is configured with the correct IP address of the DNS server
- Interface Misconfiguration
  - Users may experience no connectivity
  - Either the source or the destination device may have incorrect an IP address and subnet
  - Check the IP address and the subnet mask of both the source and destination devices
- MTU Black Hole
  - User experiences timeout when accessing certain web applications
  - When a router receives a packet that is larger than the Maximum Transmission Unit (MTU), and if that packet is flagged as "don't fragment," the router is expected to send an ICMP message "destination unreachable" back to the host that sent the packet.
  - If the router drops the packet and doesn't send the ICMP message to the host, then such router is referred to as "black hole" router.
  - Use ping utility to locate a "black hole" router.
  - The issue can be solved by setting the MTU of the host interface to the largest size that the black hole router can handle

## IOT

- Network of devices such as Appliances, vehicles, physical devices that work with sensors
- Z-Wave
  - Wireless comms protocol
  - used for home automation ( lighting, security thermostats )
  - Mesh network
  - Controlled via keypad or key fob
- Ant+
  - Wireless communications protocol
  - Monitors sensor data ( heart rate, tyre pressure , TV)
  - created and managed by ANT+ Alliance ( Garmin )
- Bluetooth Mesh Networking
  - Adopted in 2017
  - Allows for many-to-many communications
  - Receiver can be thing, group of things or many things
  - All messages encrypted and authenticated
- Near-field Communication (NFC)
  - Set of communications protocols
  - Allows for two devices (one is smartphone) to communicate
  - Need to be within 4cm of each other
  - Used for contactless payments
- Infrared (IR)
  - Inexpensive communication technology
  - Similar to visible light but slightly longer wavelength
  - Remote TV control click = 38,000 signals per second
  - Used in IoT for medical diagnostics, fire detection, remote gas leak detection
- Radio Frequency Identification (RFID)
  - Essential to the operation of IoT
  - Allows computers to mange all individual things
  - Uses electromagnetic fields to identify and track tags attached to objects
  - Tags contain electronically stored information
  - Example is tracking vehicle through manufacturing process
