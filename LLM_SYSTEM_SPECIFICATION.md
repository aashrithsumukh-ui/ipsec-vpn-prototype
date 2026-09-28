# IPsecGuard AI — Complete System Specification & Architecture

> **Document Purpose**: Complete system specification, feature catalog, skeleton structure, tech stack, and original problem statement for LLM context ingestion, downstream agent prompting, and technical auditing.

---

## 1. Original Problem Statement

```
========================================================================================
Problem Statement ID    : 26160
Organization            : National Technical Research Organisation (NTRO)
Problem Statement Title : AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
Category                : Software / Cyber Security / Defense Intelligence
========================================================================================

BACKGROUND:
Virtual Private Networks (VPNs) are fundamental to secure communication over untrusted networks. 
Among the available VPN technologies, IPsec is widely adopted across enterprise, government, 
military, and cloud infrastructures because of its ability to provide confidentiality, integrity, 
and authentication.

However, the security of an IPsec deployment depends on multiple factors, including the chosen 
cryptographic algorithms, authentication mechanisms, key exchange protocols, and operational 
mode (Tunnel or Transport). Misconfigurations, outdated cipher suites, improper key management, 
or protocol implementation flaws can significantly weaken the overall security posture.

Traditional protocol analysis tools provide packet-level visibility but often require expert 
interpretation. There is a growing need for intelligent systems capable of automatically 
evaluating IPsec configurations, detecting vulnerabilities, analyzing traffic patterns, and 
providing actionable security assessments.

OBJECTIVES & REQUIREMENTS:
1. Automated Protocol Inspection: Parse and inspect IKEv1, IKEv2, ESP, and AH protocol exchanges 
   across IPv4 and IPv6 traffic without requiring payload decryption.
2. Cryptographic & Configuration Security Evaluation: Assess encryption algorithms (3DES, AES-CBC, 
   AES-GCM), integrity algorithms, Diffie-Hellman groups, Perfect Forward Secrecy (PFS), lifetime 
   parameters, and authentication mechanisms against NIST SP 800-77 Rev. 1 & NSA CNSA guidelines.
3. Quantum Resilience Assessment: Evaluate susceptibility to Shor's algorithm and "Harvest Now, 
   Decrypt Later" (HNDL) attacks; calculate Post-Quantum Cryptography (PQC) readiness.
4. Encrypted Traffic Intelligence: Classify application traffic patterns under ESP encapsulation 
   using statistical metadata (packet length distribution, inter-arrival times, burstiness) and 
   detect anomalous/covert tunneling.
5. Threat Intelligence Mapping: Automatically cross-reference identified weaknesses against CVEs 
   (e.g., Sweet32, Logjam, Aggressive Mode credential exposure) and MITRE ATT&CK techniques.
6. Automated Remediation: Generate vendor-neutral and vendor-specific hardening recipes (strongSwan 
   swanctl.conf, Cisco IOS CLI).
7. Live Network Inspection & Peer-to-Peer Verification: Enable real-time live interface packet 
   sniffing with deep header forensics and a multi-device peer-to-peer live IPsec tunnel verification suite.
========================================================================================
```

---

## 2. Complete Technology Stack

| Layer | Component | Version / Library | Purpose |
| :--- | :--- | :--- | :--- |
| **Runtime & Core** | Python | 3.10 – 3.13 | Core backend engine and analysis pipelines |
| **API Framework** | FastAPI + Uvicorn | `fastapi>=0.110.0`, `uvicorn>=0.28.0` | Async REST API server, multipart file processing, background tasks |
| **Packet Parsing** | Scapy | `scapy>=2.5.0` | Low-level binary decoding of Ethernet, IPv4, IPv6, UDP, ESP, AH, IKE |
| **Machine Learning** | XGBoost & Scikit-Learn | `xgboost>=2.0.0`, `scikit-learn>=1.4.0` | Multi-class gradient boosted traffic classifier & Isolation Forest anomaly detector |
| **Explainable AI** | SHAP | `shap>=0.44.0` | TreeExplainer feature importance and per-flow SHAP contribution values |
| **Data Processing** | NumPy & Pandas | `numpy>=1.26.0`, `pandas>=2.2.0` | Numerical flow statistics, aggregation, matrix operations |
| **Cryptography** | Cryptography (PyCA) | `cryptography>=42.0.0` | AES-GCM/CBC encryption/decryption routines for live P2P tunnel simulation |
| **Database** | SQLite + SQLAlchemy | `sqlalchemy>=2.0.0` | Audit history persistence, run comparison tracking, metadata storage |
| **Reporting** | Jinja2 & WeasyPrint | `jinja2>=3.1.0` | Templated executive and technical HTML/PDF compliance reports |
| **Frontend UI** | HTML5 / Vanilla JS / CSS | Tailwind CSS (CDN), FontAwesome 6, Chart.js | Modern cyber-defense operations web SPA with zero build step |
| **Testing** | Pytest & AnyIO | `pytest>=8.0.0`, `pytest-asyncio` | Automated unit, regression, API, and integration test suite |
| **Automation** | Windows Batch Scripts | `start.bat`, `sync.bat` | One-click environment bootstrap, daemon runner, and Git sync |
| **Reference Testbed** | Docker & strongSwan | `docker-compose`, `strongswan:6.0` | Multi-node IPsec VPN testbed with automated PCAP capture sidecar |

---

## 3. System Architecture & High-Level Flow

```
+-----------------------------------------------------------------------------------------------+
|                                      FRONTEND SPA (HTML5 / JS / Tailwind / Chart.js)          |
|  [Tab 1: Single PCAP Audit] [Tab 2: Side-by-Side Diff] [Tab 3: Live Sniffer] [Tab 4: P2P VPN] |
+-----------------------------------------------------------------------------------------------+
                                               |  REST API / JSON / Multipart
                                               v
+-----------------------------------------------------------------------------------------------+
|                                 FASTAPI APPLICATION CORE (`ipsecguard/api/main.py`)           |
+-----------------------------------------------------------------------------------------------+
         |                     |                          |                       |
         v                     v                          v                       v
+------------------+ +--------------------+ +-------------------------+ +---------------------+
|  PCAP INGESTION  | |  FEATURE EXTRACTION| |  AI & ML INFERENCE      | |  SCORING & INTEL    |
|  & PARSING       | |  (`features/esp.py`)| |  (`ml/`)                | |  (`scoring/`)       |
|                  | |                    | |                         | |                     |
|  - IKEv1/IKEv2   | |  - 19 Flow Stats   | |  - XGBoost 8-Class      | |  - NIST SP 800-77   |
|  - ESP (Prot 50) | |  - Monotonicity    | |    Classifier           | |  - CNSA 2.0 Matrix  |
|  - AH (Prot 51)  | |  - Gap Frequency   | |  - Isolation Forest     | |  - Quantum Safety   |
|  - IPv4 / IPv6   | |  - Modularity Dete.| |  - SHAP Explainability  | |  - CVE/MITRE Map    |
|  (`parser/`)     | |  - Heuristics      | |  - Mode Inference       | |  - Auto-Remediation |
+------------------+ +--------------------+ +-------------------------+ +---------------------+
                                               |
                     +-------------------------+-------------------------+
                     |                                                   |
                     v                                                   v
+------------------------------------------+ +--------------------------------------------------+
|  REAL-TIME PACKET SNIFFER                | |  PEER-TO-PEER IPSEC TUNNEL SUITE                 |
|  (`sniffer/live.py`)                     | |  (`tunnel/peer.py`)                              |
|  - Async Scapy socket sniffer            | |  - Real IKEv2 SA Handshake Engine                |
|  - Deep Header Extractor                 | |  - AES-GCM / AES-CBC Encrypted Messaging Tunnel  |
|  - Exact IP/Port, SPI, Seq, Flags, Hex   | |  - One-Click Instant Security Audit Pipe         |
|  - TLS Application Fingerprinting        | |  - Multi-Device LAN/WAN Cross-Connection         |
+------------------------------------------+ +--------------------------------------------------+
```

---

## 4. Detailed Feature Breakdown & Implementation Skeleton

### 4.1. Passive Protocol Ingestion & Parsers (`ipsecguard/parser/`)
- **`ike.py`**:
  - Binary parser for IKEv1 and IKEv2 exchanges (UDP 500 / 4500).
  - Extracts Security Association (SA), Key Exchange (KE), Nonce (Ni/Nr), Transform Payloads (Encryption, PRF, Integrity, DH Group).
  - Flags weak legacy protocols (IKEv1 Aggressive Mode, DES, 3DES, DH Groups 1, 2, 5).
  - Handles dual-stack **IPv4 and IPv6** outer headers seamlessly.
- **`ah.py`**:
  - Parser for IP Protocol 51 (Authentication Header).
  - Extracts SPI, Sequence Numbers, and Integrity Check Value (ICV) lengths (HMAC-MD5, HMAC-SHA1, HMAC-SHA256).
  - Emits critical compliance warnings for plaintext data transfer (AH provides integrity/authentication but zero confidentiality).

### 4.2. Statistical ESP Feature Extraction (`ipsecguard/features/esp.py`)
- **Zero-Decryption Analysis**: Extracts 19 statistical flow dimensions without decrypting ESP payloads:
  1. `packet_count`: Total packets in flow.
  2. `byte_count`: Total bytes transferred.
  3. `mean_pkt_len`, `std_pkt_len`, `min_pkt_len`, `max_pkt_len`: Packet size distribution.
  4. `mean_iat`, `std_iat`, `min_iat`, `max_iat`: Inter-arrival time (jitter/latency) distribution.
  5. `burstiness`: Ratio of standard deviation to mean IAT.
  6. `fwd_bwd_ratio`: Asymmetry ratio between forward and backward directions.
  7. `esp_seq_gaps`: Count of missing ESP sequence numbers.
  8. `esp_seq_monotonicity`: Score (0.0 to 1.0) of packet ordering consistency.
  9. `pad_mod_8_ratio`, `pad_mod_16_ratio`, `pad_mod_4_ratio`: Remainder distribution indicating cipher block size.
  10. `duration_sec`: Flow lifespan in seconds.

### 4.3. Machine Learning & Explainability Engine (`ipsecguard/ml/`)
- **`traffic_classifier.py`**:
  - Multi-class XGBoost model trained across **8 encrypted traffic classes**:
    `bulk`, `email`, `icmp`, `mixed`, `video`, `voip`, `web` *(including ChatGPT/LLM streaming token bursts)*, `whatsapp`.
  - Validated using `GroupShuffleSplit` across unseen cryptographic configurations to ensure the model learns traffic behavior rather than cipher artifacts.
  - Achieves **94.12% accuracy and 0.9333 Macro F1**.
- **`anomaly.py`**:
  - Scikit-Learn `IsolationForest` unsupervised model that flags abnormal packet sizes, burst rates, and potential covert channels.
- **`explain.py`**:
  - Computes exact SHAP (`TreeExplainer`) values for each prediction, exposing the top 3 features driving the classification.
- **`heuristics.py`**:
  - Infers cipher family (`3DES-family`, `AES-CBC-family`, `AES-GCM-family`) via padding modularity.
  - Infers encapsulation mode (`Tunnel` vs `Transport`) from packet size overhead.
  - Evaluates replay protection mechanisms via sequence monotonicity.

### 4.4. Security Scoring, Standards & Intelligence (`ipsecguard/scoring/`)
- **`rules.py` (5-Domain NIST Risk Score 0–100)**:
  - Cryptographic Strength (weight: 35%)
  - Key Management & Lifetime (weight: 25%)
  - Perfect Forward Secrecy (PFS) (weight: 15%)
  - Metadata Exposure (weight: 15%)
  - Replay Protection (weight: 10%)
- **`compliance.py` (NIST SP 800-77 & NSA CNSA Suite Matrix)**:
  - Automated Pass/Fail checks across 7 critical controls:
    1. Approved Cipher Suite (AES-GCM / AES-CBC required; 3DES/DES forbidden).
    2. Secure Key Exchange (IKEv2 required; IKEv1 legacy/deprecated).
    3. Strong Diffie-Hellman Group ($\ge$ Group 14 / 2048-bit; Groups 1, 2, 5 forbidden).
    4. Perfect Forward Secrecy (PFS enabled on Phase 2 child SA).
    5. Anti-Replay Protection (Enforced ESP sequence monotonicity).
    6. Confidentiality Assurance (ESP required; AH-only flagged).
    7. NSA CNSA Suite 2.0 Alignment (AES-256, DH Group 19/20/21 or PQC ML-KEM).
- **`quantum.py` (Quantum Resilience / PQC Readiness)**:
  - Calculates Quantum Safety Index (0–100).
  - Evaluates Harvest-Now-Decrypt-Later (HNDL) risk from classical DH/ECDH key exchanges vulnerable to Shor's algorithm.
  - Rates symmetric cipher safety against Grover's algorithm (AES-128: moderate; AES-256: quantum-safe).
- **`threat_intel.py` (CVE & MITRE ATT&CK Mapping)**:
  - Maps identified misconfigurations to known vulnerabilities:
    - `CVE-2016-2183` (Sweet32 64-bit block cipher collision attack on 3DES).
    - `CVE-2015-4000` (Logjam DH Group 1/2 prime factorization attack).
    - `CVE-2002-1623` (IKEv1 Aggressive Mode Pre-Shared Key hash sniffing).
    - MITRE ATT&CK Techniques: `T1588.006`, `T1557`, `T1040`, `T1565.002`.
- **`remediation.py` (Automated Hardening Code Generator)**:
  - Generates ready-to-deploy hardening configurations for:
    - **strongSwan 6.0 (`swanctl.conf`)**
    - **Cisco IOS CLI (`crypto ikev2` & `crypto ipsec`)**

### 4.5. Real-Time Packet Sniffer & Deep Forensic Inspector (`ipsecguard/sniffer/live.py`)
- Background asynchronous Scapy sniffer capturing live interface traffic.
- Parses every packet into a forensic telemetry model:
  - `timestamp`: ISO-8601 millisecond timestamp.
  - `src_ip`, `src_port`, `dst_ip`, `dst_port`: Exact endpoints.
  - `protocol`: IPv4/IPv6, UDP, TCP, ESP, AH, ICMP.
  - `esp_spi`, `esp_seq`: Exact IPsec SPI and sequence numbers.
  - `tcp_flags`: SYN, ACK, PSH, FIN, RST.
  - `app_tag`: Application identification (ChatGPT / AI Assistant, HTTPS, DNS, WireGuard, IPsec).
  - `hex_dump`: Formatted binary payload hex and ASCII dump for deep packet forensics.
- Provides immediate export into the AI analysis pipeline.

### 4.6. Peer-to-Peer Live IPsec VPN Tunnel Node (`ipsecguard/tunnel/peer.py`)
- Standalone multi-device IPsec node that can run on any machine.
- Implements:
  - Real simulated IKEv2 SA negotiation handshake over UDP sockets.
  - Authenticated AES-GCM / AES-CBC encrypted bidirectional tunnel session.
  - Live encrypted interactive chat/data exchange.
  - In-memory PCAP generation of tunnel packets.
  - One-click instant security audit executing the complete assessment pipeline on live tunnel traffic.

### 4.7. Side-by-Side PCAP Diff Comparison Engine (`/api/compare`)
- Ingests two PCAP captures simultaneously (e.g. Baseline vs Remediated).
- Computes risk score deltas, cipher upgrades, DH changes, and compliance improvements with visual comparison cards.

---

## 5. File & Directory Skeleton

```
C:\projects\IPsec/
├── .github/
│   └── workflows/
│       └── ci.yml                      # Automated CI testing workflow
├── data/
│   └── synthetic/                      # Synthetic multi-cipher PCAP dataset
│       ├── manifest.csv                # Dataset metadata catalog
│       └── *.pcap                      # Pre-generated 3DES, AES-CBC, AES-GCM, IPv6 pcaps
├── frontend/
│   └── index.html                      # Single-page application UI (4 tabs)
├── ipsecguard/
│   ├── __init__.py
│   ├── models.py                       # Pydantic domain models & schemas
│   ├── pipeline.py                     # Master orchestration pipeline
│   ├── api/
│   │   ├── __init__.py
│   │   └── main.py                     # FastAPI REST API endpoints
│   ├── db/
│   │   ├── __init__.py
│   │   └── repository.py               # SQLite / SQLAlchemy audit persistence
│   ├── features/
│   │   ├── __init__.py
│   │   └── esp.py                      # 19-feature ESP statistical flow extractor
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── anomaly.py                  # IsolationForest anomaly detector
│   │   ├── explain.py                  # SHAP TreeExplainer feature contributor
│   │   ├── heuristics.py              # Padding modularity & tunnel mode inference
│   │   └── traffic_classifier.py       # XGBoost 8-class traffic classifier
│   ├── parser/
│   │   ├── __init__.py
│   │   ├── ah.py                       # Authentication Header (Prot 51) parser
│   │   └── ike.py                      # IKEv1/IKEv2 binary parser (IPv4/IPv6)
│   ├── reports/
│   │   ├── __init__.py
│   │   ├── render.py                   # Jinja2 / WeasyPrint report generator
│   │   └── templates/
│   │       ├── executive.html          # Executive summary template
│   │       └── technical.html          # Technical engineering report template
│   ├── scoring/
│   │   ├── __init__.py
│   │   ├── compliance.py               # NIST SP 800-77 & NSA CNSA 2.0 matrix
│   │   ├── quantum.py                  # Quantum safety & HNDL exposure index
│   │   ├── remediation.py              # strongSwan & Cisco hardening generator
│   │   ├── rules.py                    # 5-domain NIST risk scoring engine
│   │   └── threat_intel.py             # CVE & MITRE ATT&CK mapping
│   ├── sniffer/
│   │   ├── __init__.py
│   │   └── live.py                     # Live Scapy packet sniffer & deep inspector
│   └── tunnel/
│       ├── __init__.py
│       └── peer.py                     # Peer-to-Peer IPsec VPN tunnel engine
├── models/
│   ├── anomaly.joblib                  # Trained Isolation Forest model
│   ├── confusion_matrix.png            # Multi-class evaluation confusion matrix
│   ├── metrics.json                    # Accuracy (94.12%), F1 (0.9333), per-class scores
│   ├── traffic_classifier.joblib       # Trained XGBoost classifier
│   └── traffic_labels.json             # 8 class labels mapping
├── samples/                            # Demo PCAP files for immediate UI testing
├── scripts/
│   ├── synth_data.py                   # Synthetic PCAP generation engine
│   └── train_models.py                 # ML training & evaluation script
├── testbed/
│   ├── capture.sh                      # Automated tcpdump capture script
│   ├── docker-compose.yml              # strongSwan 6.0 dual-node testbed
│   └── configs/
│       ├── left/swanctl.conf           # Left peer strongSwan config
│       └── right/swanctl.conf          # Right peer strongSwan config
├── tests/
│   ├── test_ah_and_ipv6.py             # AH & IPv6 parser unit tests
│   ├── test_api.py                     # REST API endpoint tests
│   ├── test_live_and_tunnel.py         # Sniffer & P2P tunnel tests
│   ├── test_parser.py                  # IKE parser tests
│   └── test_scoring.py                 # NIST & Quantum scoring tests
├── LLM_SYSTEM_SPECIFICATION.md         # This specification document
├── PROJECT_SUMMARY_REPORT.md           # Comprehensive technical report
├── pyproject.toml                      # Package build configuration & dependencies
├── README.md                           # Project documentation & quickstart
├── start.bat                           # One-click Windows startup script
└── sync.bat                            # Git auto-staging, committing, and syncing script
```

---

## 6. Key API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/analyze` | Upload a `.pcap` file for full AI inspection, risk scoring, compliance audit, and ML classification. |
| `POST` | `/api/compare` | Upload two `.pcap` files for side-by-side diff comparison and delta analysis. |
| `GET` | `/api/history` | Retrieve past audit runs and security scores. |
| `GET` | `/api/report/{run_id}/html` | Render and download executive or technical HTML report. |
| `POST` | `/api/sniffer/start` | Start live packet sniffing on a specified interface with packet limit and duration. |
| `POST` | `/api/sniffer/stop` | Stop running live sniffer session. |
| `GET` | `/api/sniffer/status` | Fetch real-time sniffer state, packet counts, and deep forensic packet records. |
| `POST` | `/api/sniffer/analyze` | Pipe captured live packets directly into the AI security analysis pipeline. |
| `POST` | `/api/tunnel/start` | Start a local Peer-to-Peer IPsec tunnel node (mode: `host` or `client`). |
| `POST` | `/api/tunnel/connect` | Connect client node to a remote peer host address and initiate IKEv2 handshake. |
| `POST` | `/api/tunnel/send` | Transmit an AES-GCM encrypted message payload across the live tunnel. |
| `POST` | `/api/tunnel/audit` | Execute instant security compliance audit on all live tunnel session packets. |
| `POST` | `/api/tunnel/stop` | Terminate active P2P IPsec tunnel session. |

---

## 7. How to Run & Verify

1. **Start the Platform (One-Click)**:
   ```cmd
   start.bat
   ```
2. **Run Automated Test Suite (18 tests)**:
   ```powershell
   python -m pytest tests/
   ```
3. **Sync to Git Repository**:
   ```cmd
   sync.bat
   ```
