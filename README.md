# RavenThief & Nest C2

<p align="center">
<img src="https://github.com/user-attachments/assets/62f71ccf-beaf-45ce-9bf5-9aa04eaf3406" width="300"/>
<img src="https://github.com/user-attachments/assets/e7eb4cd2-957d-4300-ad09-c84e76706789" width="300"/>
</p>


## Context

This infostealer was developed by final-year students in the [SRS (Systèmes, Réseaux et Sécurité)](https://srs.epita.fr/) major at [EPITA](https://www.epita.fr/), as part of a project for the virology course. The source code has been designed exclusively for educational purposes, and is not intended for public distribution. The developers accept no liability for misuse or damage caused by this software. The use of this code for malicious or unauthorized activities is strictly forbidden. There is no need to contact us to obtain this code, as it will not be shared. This Github repository is only here to present our old project.

The aim of the project was to design a malware following a rigorous methodology, in particular by formalizing a kill chain in seven distinct stages. Students explored different modes of infection, propagation and command and control (C2) adapted to corporate environments. An essential part of the work involved defining “target actions”, i.e. relevant active loads, and designing lateral movement mechanisms within IT systems. The project had to be compatible with at least two different operating systems, including Windows and other: Linux, Mac, as well as mobile systems, etc. In addition, it was crucial to implement stealth and self-defense features to guarantee the stealth of the code developed. The project was validated by a live demonstration, in the form of a realistic demo.

In terms of security, it was imperative that all storage locations for source code and compiled code be protected by strict access control. The use of VirusTotal or Hybrid Analysis was forbidden for compiled versions of project binaries in debug mode. Additionally, antivirus sampling functions were to be disabled on development and test computers. The C2 was to be hosted on the local network by default, and both the malware and C2 had to include a killswitch to prevent their use outside of the test environment. The project was to be carried out by groups of 3 to 8 students, with higher requirements for larger groups.

## Nest C2: The Command & Control of RavenThief

<p align="center">
<img src="https://github.com/user-attachments/assets/e7eb4cd2-957d-4300-ad09-c84e76706789" width="300"/>
</p>

Nest C2 is a Command and Control center (C2), for RavenThief infostealer, primarily developed in JavaScript. Its purpose is to facilitate all levels of the kill chain, including exploitation, reconnaissance, post-exploitation (such as exfiltration), and more. Designed to be simple to use, it was created to be operable without technical requirements (similar to how infostealers are sold in real-world scenarios). Communication between the C2 and the malware RavenThief is implemented using Notion as a proxy, allowing for more stealthy operations (e.g [APT29 using Notion's API](https://mrtiepolo.medium.com/sophisticated-apt29-campaign-abuses-notion-api-to-target-the-european-commission-200188059f58)).

</br>
<p align="center">
    <img align=top width="49%" src="https://github.com/user-attachments/assets/c05dec95-03d9-476e-9822-20e222e8bf83"/>
    <img align=top width="49%" src="https://github.com/user-attachments/assets/51a62b33-ae1f-45e9-9cc1-27a565fca8f9"/>
</p>

## Nest C2's Key Features

| C2 Feature                     | Description                                                                                                                                                                                                                                                                                                     |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Intuitive Interface**     | Nest C2 provides an intuitive web application to easily run large-scale collaborative red team operations, managing users and team-specific administrator access. The C2 offers total granular control.                                                                                                   |
| **IP Location**             | Nest C2 enables the localization of the IP addresses of the victims.                                                                                                                                                                                                                                       |
| **Friendly Design**         | Nest C2's user-friendly design simplifies navigation and operation, ensuring that users can effectively interact with the platform.                                                                                                                                                                          |
| **Target Management**       | Nest C2 allows teams to orchestrate multiple attacks across various entry points, synchronizing different aspects of the kill chain, including lateral movement.                                                                                                                                               |
| **Turnkey Solution**        | Nest C2 is fully automated, simplifying its use even for individuals without prior experience in cybersecurity.                                                                                                                                                                                            |
| **Multi-Platform**          | The C2 of RavenThief is coded in Node.js, which is multi-platform. It can also be launched via a Docker Compose file, enabling it to run natively on Linux, macOS and Windows. Additionally, RavenThief supports Docker, allowing it to run within a container on any system with Docker installed. |
| **Multi-User Support**      | Nest C2 supports multi-user collaboration, allowing many users to interact with the same RavenThief server and operate independently or collaboratively, which is crucial for effective red team operations.                                                                                                 |
| **API Driven**              | Nest C2 is driven by an API that facilitates multi-user collaboration and is easily extendable due to its modular architecture. Additionally, it includes a Swagger UI that simplifies development and debugging.                                                                                              |
| **Variety of Add-ons**      | Nest C2 offers integration with Notion, Google Drive, and Teams, enhancing its functionality and usability.                                                                                                                                                                                                 |
| **Easily Scalable**         | Nest C2 is designed to be easily scalable due to its massively parallel microservices architecture.                                                                                                                                                                                                          |
| **Encrypted Key Exchange**  | Nest C2 uses an encrypted key exchange between implants and C2, utilizing TLS protocols provided by the add-ons.                                                                                                                                                                                           |
| **Dynamic Compilation**     | Nest C2 allows dynamic compilation, enabling users to select the OS on which the implant should run, making it well-suited for various scenarios and targets.                                                                                                                                                   |
| **One-Click Compilation**   | Nest C2 enables one-click compilation of implants directly from the dashboard, streamlining the process.                                                                                                                                                                                                     |
| **Golang Developed Implants** | Nest C2 implants are entirely coded in Golang, facilitating the addition of new features and ensuring secure code.                                                                                                                                                                                        |

### C2's architecture :
Nest C2 features a modular and massively parallel architecture that optimizes scalability. This architecture can be divided into three main components:

<p align="center">
<img src="https://github.com/user-attachments/assets/de52ad48-d950-4a0c-a5bc-46e66c873d55" width="700"/>
</p>

#### Scheduler/Backend
This component acts as the brain of the command and control system. It manages the REST API for communication with the frontend and also handles the communication logic with the malware through Notion. Multiple workers operate simultaneously to synchronize the database and Redis cache. This synchronization is crucial for coordinating tasks among workers. Additionally, the backend is responsible for managing communication with Notion and sending commands to the malware. By leveraging parallel processing, the system can efficiently handle numerous operations at once, ensuring smooth communication and rapid response times.

#### Frontend
The frontend provides users with a simple and intuitive graphical interface. Built with ReactJS, it includes various features to enhance usability. Key components of the frontend include

- A dashboard that summarizes essential information, such as active targets, stolen files, and other critical data, giving users an overview of the system's current state.

![Peek 2024-08-27 02-08](https://github.com/user-attachments/assets/1048fed2-5cb2-461b-8234-0da75b0b28a1)


- A "Targets" page that allows users to create, delete, and manage targets under attack, providing control over the entire targeting process.

![Peek 2024-08-27 02-19](https://github.com/user-attachments/assets/1fb246f1-d87c-472a-8813-515a43406667)


- A "Workstation" page that facilitates the management of attacks on specific targets. This page enables users to perform various actions, such as lateral movement, information gathering, privilege escalation, and other tasks necessary to penetrate and control target systems.

![Peek 2024-08-27 02-02](https://github.com/user-attachments/assets/30c6920c-46d2-430b-94b9-7bb85edd13fc)



### Notion Proxy :

<p align="center">
<img src="https://github.com/user-attachments/assets/2e127b9b-cc95-4fae-802a-d080e2056c84" width="500"/>
<img src="https://github.com/user-attachments/assets/ea5eedb6-3d53-44cd-b547-c48064e1a9d2" width="500"/>
</p>

Inspired by [Notionion](https://github.com/ariary/Notionion), we utilized Notion as a proxy to conceal NestC2 within the victim's information system. NestC2 communicated with Notion, while the RavenThief implant on the victim's system monitored a Notion page for new commands.

## RavenThief: A simple Infostealer

<p align="center">
<img src="https://github.com/user-attachments/assets/62f71ccf-beaf-45ce-9bf5-9aa04eaf3406" width="300"/>
</p>

## RavenThief's Key Features

| Implant Feature                     | Windows       | Linux        |
|-----------------------------|---------------|--------------|
| **Privilege Escalation**    | Yes           | Yes          |
| **Lateral Movement**        | Yes (not automatic) | Yes      |
| **Data Exfiltration**       | Yes           | Yes          |
| **Anti-Debug**              | Yes           | Yes          |
| **Persistence**             | Yes           | Yes          |
| **Rootkit**                 | No            | Yes          |
| **Proxy (Bounce)**          | Yes           | Yes          |
| **Download File**           | Yes           | Yes          |
| **File Explorer**           | Yes           | Yes          |
| **Shell**                   | Yes           | Yes          |

### MITRE ATT&CK Mapping :

<p align="center">
<img src="https://github.com/user-attachments/assets/745e040f-45ff-4467-8a49-bcb39529aa28" width="700"/>
</p>

🟦: Common features of the malware on Windows and Linux

🟨: Malware features on Windows

🟩: Malware features on Linux

#### Reconnaissance (From Nest C2):
Scans are also conducted using **Nmap** through the package [**stnw**](https://www.npmjs.com/package/stnw), which was specifically created for this purpose. The Command and Control (C2) system performs reconnaissance based on the **Apache CVE-2021-41773** vulnerability by sending HTTP requests. This CVE allows for **Remote Code Execution (RCE)** on vulnerable servers, providing initial access to the target system.
<p align="center">
<img src="https://github.com/user-attachments/assets/364b2124-4bd4-4911-80d2-c42aa04ac009" width="49%"/>
<img src="https://github.com/user-attachments/assets/7be363dd-8e2d-4f66-b842-3a5577ec32eb" width="49%"/>
</p>
Additional CVEs could have been integrated into this functionality of our C2 system, but for the purposes of this exercise, we have only implemented CVE-2021-41773. 

#### Initial Access:
Multiple initial access methods can be used. One option is to leverage the remote scan feature, which enables initial access by exploiting a list of vulnerabilities. Alternatively, malware can be generated based on the target machine's operating system. The execution method is left to the user’s discretion, whether it’s via Rubber Ducky, phishing, or other means. The malware is available for Linux, Windows, and Mac. Simply select the target OS in the settings and click "Download Malware."
<div align='center'>
<p>
    <img src='https://github.com/user-attachments/assets/3389a30d-7741-4167-856d-2b7a60bb1612' width="50%" align='center'/>
    <center><i>User-friendly feature for vulnerability scanning (CVE) and their exploitation from the C2</i></center>
</p>
<p>
    <img src='https://github.com/user-attachments/assets/5b559a9e-f641-4328-8794-106c11919970' width="50%" align='center'/>
    <center><i>Feature allowing the download of an implant based on the target's OS</i></center>
</p>
</div>

#### Execution:

The communication and execution were heavily inspired by Cobalt Strike and techniques used by APT29. The malware never communicates directly with the C2; instead, it uses a Notion page to benefit from both TLS encryption and the reputation of the site, thus leveraging the trust sysadmins place in it. Commands and responses are transmitted as JSON, which specifies the structure of the request. Each request contains several fields: the source (whether the command originates from the C2 or a pivot machine), the command to be executed on the target machine, the IP path to be followed (representing intermediate nodes for lateral movement), and a field representing the result of the command.

```json
{
    "from": "C2",
    "to": "M3",
    "command": "getUserAndGroups",
    "path": ["192.168.1.2"],
    "value": "{ .... }",
}
```

In some cases, the malware can use a machine as a pivot to communicate with the C2, reducing the number of network requests and bypassing security measures such as DMZs or network segmentation that might prevent direct communication between PCs and the internet. This approach ensures stable and discreet communication with all infected systems.

<p align='center'>
    <img src='https://github.com/user-attachments/assets/c8364dc8-b32f-4e75-884b-396bdb453d32' width="50%" align='center'/>
</p>

The "path" field, as the name suggests, describes the route to reach the target machine. It functions as a queue, where each encountered node "pops" the current IP, exposing the next one. A node corresponds to an infected machine that proxies requests to other machines via lateral movement.

<p align='center'>    
    <img src='https://github.com/user-attachments/assets/7bff1df4-fac5-4e11-80cd-b416254348bc' width="50%" align='center'/>
</p>

#### Persistence:
> Persistence is the ability of malware or an attacker to maintain access to a system after reboots, logouts, or updates. It’s crucial because it ensures continuous control without needing to re-exploit vulnerabilities. This enables long-term operations, data harvesting, and further attacks (e.g., lateral movement). Without persistence, access could easily be lost after a reboot or patch.

Persistence in Linux is achieved through two main stages: one when the user has limited privileges and another when a privilege escalation to root has been successful. The Linux persistence mechanism consists of the following steps:
- Limited privileges: Persistence is maintained using the CronJob scheduler, where a job is added to periodically execute the implant as a background task. This ensures the malware continues to run at scheduled intervals.
- Root privileges: Once root access is obtained, a more advanced persistence method is implemented through a rootkit. This is done by overloading the LD_PRELOAD environment variable, which allows the attacker to intercept and modify the system’s syscalls (system calls). This gives the attacker continuous privileged access and makes the implant harder to detect and remove.

For persistence on Windows systems, we have implemented techniques using the Windows Task Scheduler. This method allows the malware to be automatically executed at scheduled intervals or triggered by certain system events (e.g., at login or system startup). Here's how it works:
- Scheduled Tasks: A task is created within the Task Scheduler to run the malware at specific times or under specific conditions (e.g., every time the user logs in or the system boots up). This ensures that even after a reboot, the malware will automatically execute and maintain control over the system. Additionally, persistence techniques can include:
    - Registry Modification: By modifying certain keys in the Windows registry, we can ensure that the malware is executed at startup.
    - Service Creation: The malware can create a hidden or disguised service that runs continuously in the background, making it harder for users or administrators to detect and stop.


#### Privilege Escalation:
> Privilege escalation refers to gaining higher-level permissions on a system than originally granted, often moving from a lower, restricted user role to an administrator or root level. This is crucial for attackers because it allows them to bypass security restrictions, access sensitive data, or execute privileged operations that would otherwise be blocked.

For privilege escalation, RavenThief uses a UAC Bypass technique on Windows by leveraging ComputerDefaults. This method allows an attacker to execute code with elevated permissions without triggering a UAC prompt. The ComputerDefaults.exe binary, a legitimate component of Windows, is frequently exploited in this bypass technique because it can launch other processes with administrative privileges. Attackers manipulate or hijack this process to execute their malicious payloads, effectively bypassing UAC protections. This technique has also been part of the Tactics, Techniques, and Procedures (TTP) employed by the APT group known as Earth Preta (also referred to as Mustang Panda). Earth Preta has been associated with cyber-espionage campaigns, primarily targeting government and non-governmental organizations in Southeast Asia, using UAC bypass methods to gain elevated privileges and maintain persistence in their attacks.

On Linux distributions, RavenThief exploits CVE-2023-4911, also known as Looney Tunables. This is a critical vulnerability discovered in the GlibC (GNU C Library), affecting multiple Linux distributions. The flaw resides in the handling of the GLIBC_TUNABLES environment variable, allowing attackers to achieve privilege escalation or remote code execution (RCE) by exploiting improper input validation. The vulnerability impacts several major Linux distributions, including Fedora 37 and 38, Ubuntu 22.04 and 23.04, and Debian 12 and 13, among others. The Kinsing threat actor group has been observed actively exploiting Looney Tunables to compromise cloud environments in the wild.

#### Defense Evasion:
> Defense evasion refers to the techniques employed by attackers to avoid detection and thwart security measures put in place to protect systems and networks. Including defense evasion strategies in RavenThief is crucial for several reasons, primarily to ensure the longevity of the attack and to minimize the risk of being discovered by security personnel or tools.

For Defense Evasion on Linux distributions, RavenThief employs several techniques to detect whether it is being analyzed or debugged. It specifically checks for the presence of GDB (GNU Debugger) or pTrace being used to monitor its execution. Additionally, it inspects other system characteristics that may indicate a controlled environment, such as the presence of VDSO (Virtual Dynamic Shared Object), the status of Address Space Layout Randomization (ASLR), and the existence of debugging-related environment variables. Upon identifying these indicators, RavenThief can terminate its execution to evade analysis and maintain its stealth.

On Windows, RavenThief enhances its Defense Evasion capabilities by retrieving the list of running processes and comparing the names of executables against a predefined list of debugger-related processes. This list includes names associated with common debugging tools such as OllyDbg, WinDbg, x64dbg, and others. If any of these debugger processes are detected, RavenThief terminates its execution to avoid detection and analysis by security researchers or forensic tools.

In addition, RavenThief possesses a killswitch mechanism. If the malware loses communication with its Nest C2 after failing to receive responses to its "I am alive" calls, it triggers its evasion procedure. This process involves systematically shutting down and deleting each implant to ensure that no traces of its presence remain on the network, effectively removing any footprint of its activities.

#### Lateral Movement:
> Lateral movement refers to the techniques attackers use to move from one compromised system to another within a network, expanding their reach and control. Including lateral movement in RavenThief is essential because it allows attackers to navigate deeper into the network, gaining access to additional systems, accounts, and data that they wouldn't have access to from the initial compromised machine. This increases the attacker's ability to compromise sensitive targets, escalate privileges, and execute larger-scale attacks like ransomware deployment or data exfiltration.

In RavenThief, lateral movement is implemented through the abuse of the Apache CVE-2021-41773, allowing remote code execution on vulnerable machines. However, the malware's modular architecture makes it highly adaptable, enabling the easy addition of new modules, making it agile and capable of utilizing other vulnerabilities as needed.
Additionally, RavenThief offers attackers the ability to open a reverse shell on any compromised machine. This gives experienced attackers direct control to perform custom lateralization techniques, such as NTLM relay attacks, Kerberoasting, or other manual exploits, making the malware flexible for a variety of attack strategies.
Connections between compromised machines are represented within the C2 as links, enabling the malware to use parent machines as proxies or pivot points. This allows attackers to route their traffic through different nodes in the network, enhancing stealth and reducing the likelihood of detection by security systems.
By including lateral movement, RavenThief not only extends the attack’s reach but also strengthens persistence, adaptability, and stealth across the network.

<p align="center">
<img src="https://github.com/user-attachments/assets/cb96beb5-a47c-448f-b3e6-ee6cefe393f8" width="45%"/>
<img src="https://github.com/user-attachments/assets/5bca1974-958a-43a6-84fe-141677eb0e9e" width="45%"/>
</p>

#### Exfiltration:
In RavenThief, data exfiltration is carried out slowly and discreetly. Text-based data, such as credentials or logs, is exfiltrated via a Notion page, taking advantage of the platform’s TLS encryption to secure the communication. Notion’s trusted reputation further helps evade detection by system administrators or security tools, as traffic to and from Notion may be seen as legitimate.

For file exfiltration, RavenThief uses the service Temp.sh. This service allows files to be uploaded temporarily, and the malware communicates the download link back to the attacker through the Notion page. This two-step process—uploading the file to Temp.sh and sharing the link via Notion—adds an additional layer of indirection, further reducing the chances of detection and ensuring the exfiltration remains under the radar.

By leveraging legitimate services and implementing a slow, methodical exfiltration strategy, RavenThief enhances its ability to steal sensitive data without being detected, making it a highly effective tool for attackers seeking long-term data extraction from compromised systems.

<p align="center">
<img src="https://github.com/user-attachments/assets/33315c56-fde3-4a91-885c-0a42e0dade51" width="45%"/>
<img src="https://github.com/user-attachments/assets/2016f413-2d86-4360-bbdc-e910061bfdc1" width="45%"/>
</p>



### VirusTotal Detection

**Linux Implant :**
<p align="center">
<img src="https://github.com/user-attachments/assets/1b5ac7e8-5d17-4750-8625-1045041a69cd" width="50%"/>
</p>

**Windows Implant :**
<p align="center">
<img src="https://github.com/user-attachments/assets/77595afc-0a58-466a-a670-2454c286fa29" width="50%"/>
</p>

### Last Disclaimer
This C2 and malware were developed by students at EPITA (https://www.epita.fr/) from the SRS major (https://srs.epita.fr/) as part of a project in a Virology course. The code is intended for educational purposes only and is not meant for public release. The developers hold no responsibility for any misuse or damage caused by this software. Usage of the code for malicious or unauthorized activities is strictly prohibited.


## Authors
- [Alb-310](https://github.com/Alb-310/)
- [Yasha-Ops](https://github.com/Yasha-ops/)
- [Ced-G](https://github.com/Ced-G/)


