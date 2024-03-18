- Virtualization is the process of separating the operating system from the underlying hardware. 
- This leads to the independence of operating system from the hardware resources. 
- Hypervisor is the core technology that works behind virtualization.

![](https://i.imgur.com/7zXPwFf.png)
## Hypervisor 

- Application that separates operating system and other apps from the underlying physical hardware. 
- Allows a physical machine to run multiple virtual machines as guests.
- Example : VMware hypervisor (ESXi)
- Hypervisor plays the role of host application and the virtual machines are considered as a guest.
- Hypervisor creates an abstraction layer over the computer hardware.
- Hardware elements are divided into multiple virtual machines
- Each virtual machine runs its own operating system independently.
![](https://i.imgur.com/HNpmpP9.png)

## Virtual Desktop Infrastructure

![](https://i.imgur.com/TaitUxl.png)


## Desktop Virtualization 

- Desktop virtualization: Technology that abstracts the operating system from the hardware. 
- VDI: A type of desktop virtualization that uses a connection broker to allow end-users to connect to their virtual desktops from anywhere. It is the infrastructure that makes the Virtualization possible. 
- ![](https://i.imgur.com/z5pRdkt.png)
- Server and Desktop Virtualization:
	- Server - virtualizing physical servers in the datacenter 
	- Desktop - virtualizing end user desktops into the datacenter
		- connected via broker
		- linked clones from a single image
	- They are basically same as they run on a hypervisor, on virtual hosts, and in the data center. 
- ![](https://i.imgur.com/vdnHTxN.png)

## Application Virtualization 

- decouples applications from the operating system (OS), eliminating the need for installation.
- enables easier management of applications and makes them independent of the underlying OS.
- Most Virtual Desktop Infrastructure (VDI) setups incorporate application virtualization to streamline the management of end-user applications. Some setups integrate application virtualization management within the same interface used for desktop virtualization.
- End users or their devices can be assigned virtualized applications, simplifying access and management.
- Examples of application virtualization solutions include:
  - VMware ThinApp and View
  - Citrix XenApp and XenDesktop

## Advantages of VDI

- Data center capabilities for virtual desktops - DR/BU/HA
- Low cost of rolling out new apps and OS to end users
- Imaging & linked clones for end user desktops
- Separate between user data, programs, and OS
- Refresh cycle for end user devices is much longer
- Easy remote access for end users to their desktop, through various devices
- very quick provisioning of new desktops

## Limitations of VDI 

- Initial design and setup can be complex
- Certain apps can cause issues or not perform well
- Remote users are dependent on connection to central datacenter
- Datacenter and network downtime can cause all users to be down
- May have higher upfront costs (which are returned in the long run with lower support costs)
- Central datacenter and network must be properly designed and understood

## Terminal Services 

- Utilize the Windows Server OS to enable multiple remote users to share the OS and applications.
- Terminal Services (TS) has been rebranded as "Remote Desktop Services" (RDS) since Windows Server 2008 R2.
- RDS is fully supported by Microsoft, requiring only the activation of terminal services.
- Install applications once, allowing users to run their individual instances.
- Users access the server via Remote Desktop Protocol (RDP) using thin client devices or PCs/laptops configured as thin clients.
- A single server can support 60+ end users, demonstrating scalability and efficiency.

| Feature                      | VDI                                                                                               | Terminal Server / RDS                                                               |
| ---------------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Individual VM for every user | Each user gets their own virtual machine, providing isolation and customization.                  | Users share the same OS and applications, lacking individual virtual machines.      |
| Custom user experience       | Users can have more customized desktops and applications within their VMs.                        | Limited customization as users share the same OS and applications.                  |
| Application compatibility    | Generally fewer issues with application compatibility as each VM can have its own configurations. | Possibility of compatibility issues due to shared OS and applications.              |
| Complexity of design         | More complex design due to individual VMs and management overhead.                                | Relatively simpler design as it involves sharing resources among multiple users.    |
| Implementation cost          | More costly due to the need for multiple VMs and associated infrastructure.                       | Generally less expensive to implement as it involves sharing resources among users. |
| Vendor support               | Most applications are supported since each user has their own environment.                        | Some applications may not be fully supported due to shared environment.             |
![](https://i.imgur.com/H7LOGFL.png)

## Remote Desktop Services 

- RDS components are: 
	- RDSH : remote desktop session host
	- RDWA : remote desktop web access
	- RDG : remote desktop gateway
	- RDVH : remote desktop virtualization host
	- RDCB : remote desktop connection broker

![](https://i.imgur.com/4vtfUWG.png)

- Session Virtualization with RDSH (Remote Desktop Session Host)
	- Terminal server model
	- Shared Apps on a shared OS

- Desktop Virtualization with RDVH (Remote Desktop Virtualization Host)
	- Desktop virtualization model
	- Individual VM for each end user or device
	- Uses Hyper-V server

- The RDCB (Remote Desktop Connection Broker) makes the determination
>


