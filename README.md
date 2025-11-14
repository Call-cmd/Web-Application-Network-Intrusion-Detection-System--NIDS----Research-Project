<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg" />
  <img src="https://img.shields.io/badge/Framework-Scikit--Learn-orange.svg" />
  <img src="https://img.shields.io/badge/Library-XGBoost-green.svg" />
  <img src="https://img.shields.io/badge/Library-LightGBM-lightgrey.svg" />
  <img src="https://img.shields.io/badge/Traffic-DVWA%20Simulated-red.svg" />
  <img src="https://img.shields.io/badge/Flow%20Extraction-CICFlowMeter-yellow.svg" />
  <img src="https://img.shields.io/badge/Attacks-SQLi%20%7C%20XSS%20%7C%20Bruteforce-critical.svg" />
  <img src="https://img.shields.io/badge/Dataset-Kaggle-blueviolet.svg" />
  <img src="https://img.shields.io/badge/Status-Research%20Project-success.svg" />
</p>

# Web Application Network Intrusion Detection System (NIDS) – Research Project

This repository contains the full workflow for developing a machine-learning–based Network Intrusion Detection System (NIDS) focused on detecting application-layer web attacks:

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Brute-Force Authentication Attacks
- Benign Web Traffic

The project integrates automated attack simulation, packet capture, flow-based feature extraction, dataset preprocessing, and model training to produce a robust intrusion detection model capable of identifying web-application threats.

---

## Project Overview

This project constructs a hybrid dataset derived from:

1. Public SQL Injection datasets (Kaggle)
2. SQLMap-generated SQLi traffic against DVWA
3. XSStrike-generated XSS payloads
4. Custom reflection-based attack scripts
5. Brute-force authentication attempts
6. Benign traffic captures

Captured packets are processed using CICFlowMeter to extract flow-based features, which are then cleaned, balanced, and used to train multiple ML classifiers.

---

## Repository Structure

```
RESEARCH PROJECT SCRIPTS/
│
├── Attack Scripts/
│   ├── Attack setup.md
│   ├── attack_script.py
│   ├── bruteforce_script.py
│
├── Dataset Processing/
│   ├── SQL Dataset Preprocessing.ipynb
│   ├── XSS Dataset Preprocessing.ipynb
│   ├── final_sqli_dataset.csv
│   ├── xss_dataset.csv
│
├── Datasets/
│   ├── final_sqli_dataset.csv
│   ├── Payloads.csv
│   ├── rockyou.txt
│   ├── sql_benign.txt
│   ├── sql_mal.txt
│   ├── xss_benign.txt
│   ├── xss_mal.txt
│
├── EDA & ModelEval/
│   ├── Web_Application_NIDS_EDA_and_Model_Training.ipynb
│
└── (PCAP files captured externally)
```

---

## Attack Simulation Pipeline

All attacks are executed against a DVWA instance hosted in VirtualBox.

### Attack Scripts

| Script | Purpose |
|--------|---------|
| attack_script.py | Generates SQLi or XSS traffic by sending payloads and detecting reflection |
| bruteforce_script.py | Simulates repeated login attempts |
| Wordlists | Define malicious and benign payload variations |

### Packet Capture

Loopback capture:

```bash
sudo tcpdump -i lo -w dvwa_traffic.pcap port 80
```

Host-only VirtualBox capture:

```bash
sudo tcpdump -i vboxnet0 -w dvwa_traffic.pcap host <DVWA_IP>
```

---

## Dataset Construction

### SQL Injection Dataset

Hybrid dataset from:

- Kaggle SQL Injection dataset
- SQLMap-generated attack payloads
- Curated benign SQL patterns

### XSS Dataset

Generated using:

- XSStrike payload generation
- Reflection-based XSS detection
- Manually crafted benign and malicious samples

### Brute-Force Dataset

Created via:

- rockyou.txt wordlist
- brute-force script
- Packet capture during repeated login attempts

---

## EDA and Model Training

`Web_Application_NIDS_EDA_and_Model_Training.ipynb` includes:

- EDA and feature inspection
- PCA visualisation
- SMOTE balancing
- Model training (RF, XGB, LGBM, KNN, SVM)
- Confusion matrices, F1-score, ROC-AUC
- Runtime benchmarking

---

## Technologies Used

- DVWA
- VirtualBox
- SQLMap
- XSStrike
- tcpdump
- CICFlowMeter
- Python (scikit-learn, pandas, numpy, xgboost, lightgbm)
- Jupyter Notebook
- VS Code

---

## Usage Instructions

1. Start DVWA in VirtualBox  
2. Begin packet capture using tcpdump  
3. Run attack scripts  
4. Convert PCAP files using CICFlowMeter  
5. Run preprocessing notebooks  
6. Train and evaluate models in the EDA notebook  

---

## Authors

**Mandisa Nyadenga**  
BTech (Hons) Computer Engineering, CPUT  

**Supervisor:**  
**Dr. O. P. Babalola**  
Cape Peninsula University of Technology (CPUT)
