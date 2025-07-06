# 🎯 Dynamic Phishing with MITM Attack – Cybersecurity Simulation

**Author**: Rei Naftali  
**Institution**: ORT Rehovot College  
**Track**: Practical Software Engineering - Cybersecurity Specialization  
**Project Type**: Final Project – Educational Simulation  
**Language**: Python  
**Status**: Completed 2023✅  

---

## ⚠ Legal & Ethical Disclaimer

> This system is an **educational simulation** designed strictly for learning and demonstration purposes.  
> Do **not** use it for malicious purposes or on real-world networks without **explicit authorization**.  
> All activities were conducted in a **controlled academic environment** as part of an officially supervised final project.  
> The project emphasizes awareness of network vulnerabilities, and aims to teach defensive and detection methods.

---

## 🧠 Project Summary

This project implements a **Man-in-the-Middle (MITM)** attack simulation combined with a **dynamic phishing system**.  
It intercepts traffic within a local network, identifies unencrypted communication with sensitive sites (e.g., login pages),  
and dynamically generates cloned websites to perform phishing via **DNS Hijacking** and **HTTP POST sniffing**.  
Traffic is relayed using **IP Forwarding** to maintain transparent connectivity while extracting sensitive credentials.

---

## 🔧 Core Features

- 🧬 **ARP Spoofing Engine**: Redirects victim traffic through attacker using ARP poisoning.
- 🧠 **Behavioral Learning**: Detects high-value targets by analyzing user browsing habits.
- 🧪 **Website Scraper & Cloner**: Dynamically clones target login pages using real-time scraping.
- 🌐 **DNS Hijacking**: Redirects specific DNS requests to fake local servers using NetfilterQueue.
- 🛰️ **Phishing Web Server**: Hosts HTTP-based fake login pages built on Flask.
- 🔍 **HTTP Sniffer**: Captures POST requests including credentials and session cookies.
- 📡 **IP Forwarding**: Forwards real traffic to preserve internet functionality.
- 📁 **Logging System**: Real-time logging of intercepted data per victim.
- 🧾 **Historical View**: Displays attack data per IP from prior sessions.

---

## 🛠️ Technologies & Tools

| Component       | Stack / Tool                          |
|----------------|----------------------------------------|
| Programming     | Python 3.8+                            |
| Network Attack  | Scapy, NetfilterQueue, socket, os      |
| Web Server      | Flask (for fake pages)                 |
| Interface       | HTML5, CSS (static templates)          |
| Data Storage    | SQLite (for logs), JSON                |
| Platform        | Windows (target), Linux (supported)    |
| Automation      | ngrok (optional for tunneling)         |
| MITM Core       | ARP Spoofing + DNS Redirection         |

---

## 🚀 Getting Started

1. **Clone this repository**  
   ```bash
   git clone https://github.com/your-username/dynamic-mitm-phishing.git
   cd dynamic-mitm-phishing
   ```

2. **Create a virtual environment** (optional)  
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

4. **Run MITM attack scripts with admin privileges**  
   - Start `arp_spoof.py`, then `dns_spoof.py`
   - Launch Flask server to serve phishing pages

---

## 📚 Educational Value

This project teaches:
- Layer 2 (ARP) and Layer 3 (IP) manipulation
- Phishing methodologies and detection techniques
- DNS spoofing and secure vs. insecure traffic
- Real-time packet interception and behavioral analysis
- The importance of HTTPS, encryption, and network segmentation

---

## 📝 License

This project is intended for **educational use only**.  
Unauthorized use, real-world exploitation, or deployment on networks without permission is **strictly prohibited**.

---

## 👥 Credits
- **Developed as part of**: Israeli Ministry of Education Final Project Certification
