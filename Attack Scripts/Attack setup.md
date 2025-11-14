# Attack Setup Instructions

These instructions describe how to run simulated web-application attacks against the DVWA environment and capture the resulting network traffic for analysis.

---

## 3. Running the Attack Scripts

Two Python scripts are used to generate malicious traffic targeting DVWA.

### 3.1 Brute-Force Attack

Executes multiple username/password attempts against DVWA’s brute-force module:

```bash
python3 ~/Downloads/bruteforce_script.py
```

### 3.2 Payload-Reflection Attack (SQLi / XSS)

This script sends payloads to a vulnerable parameter and detects whether they are reflected in the application’s response.  
It can simulate SQL Injection or Reflected XSS depending on configuration.

```bash
python3 ~/Downloads/attack_script.py
```

Ensure the script is configured with:

- **Target URL**  
  Example: `/vulnerabilities/sqli/` or `/vulnerabilities/xss_r/`
- **Parameter name**  
  Example: `id`, `name`
- **Payload wordlist**  
  Example: `sql_benign.txt`, `xss_mal.txt`

---

## 4. Capturing Traffic with tcpdump

Start `tcpdump` *before* launching any attack script to ensure all traffic is captured.

### 4.1 Local DVWA (loopback)

If DVWA is accessed via `127.0.0.1`:

```bash
sudo tcpdump -i lo -w dvwa_traffic.pcap port 80
```

### 4.2 DVWA in VirtualBox (host-only network)

If DVWA uses a VirtualBox host-only IP:

```bash
sudo tcpdump -i vboxnet0 -w dvwa_traffic.pcap host <DVWA_IP>
```

### 4.3 Capture only HTTP traffic

```bash
sudo tcpdump -i <interface> port 80 -w dvwa_http_capture.pcap
```

Replace `<interface>` with `lo`, `eth0`, `vboxnet0`, or the adapter used by DVWA.

---

## 5. Workflow Summary

1. Start DVWA in VirtualBox or local environment.  
2. Begin packet capture using `tcpdump`.  
3. Run one of the attack scripts:  
   - `bruteforce_script.py`  
   - `attack_script.py`  
4. Stop `tcpdump` once the attack completes.  
5. Convert `.pcap` files into flow-based `.csv` using CICFlowMeter.

---
