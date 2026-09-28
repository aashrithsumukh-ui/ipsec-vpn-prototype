# IPsecGuard AI — Executive Project Summary Report

**Organization**: National Technical Research Organisation (NTRO)  
**Problem Statement ID**: 26160  
**Title**: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework  
**Theme**: Blockchain & Cybersecurity  

---

## 1. Executive Summary

**IPsecGuard AI** is an intelligent, defense-grade cybersecurity framework designed to passively analyze IPsec VPN deployments without decrypting ESP payloads. It autonomously discovers cryptographic parameters from plaintext handshakes, infers operational characteristics from encrypted flow dynamics via machine learning, evaluates compliance against NIST & CNSA standards, correlates vulnerabilities with MITRE ATT&CK and CVE threat intelligence, performs live network interface sniffing, and facilitates multi-device peer-to-peer IPsec VPN tunnel verification.

---

## 2. Core Architecture & Intellectual Integrity

```
                                    +-------------------------------------------------------------+
                                    |         RAW PCAP CAPTURE / LIVE NETWORK STREAM / TUNNEL     |
                                    +------------------------------+------------------------------+
                                                                   |
                                  +--------------------------------+--------------------------------+
                                  |                                                                 |
                                  v                                                                 v
                    +---------------------------+                                     +---------------------------+
                    |    IKE / AH PARSER        |                                     |    ESP FLOW EXTRACTOR     |
                    |   (Plaintext Binary)      |                                     |  (Encrypted Flow Metadata)|
                    +-------------+-------------+                                     +-------------+-------------+
                                  |                                                                 |
                                  v                                                                 v
                     [ OBSERVED FINDINGS ]                                           [ 19 METADATA FLOW FEATURES ]
                     • IKE Version (v1 / v2)                                         • Size Mean / Std / Quantiles
                     • Transform Proposals                                           • Inter-Arrival Time Stats
                     • Diffie-Hellman Group                                          • Directional Byte Ratios
                     • PRF / Integrity Suites                                        • Mod 4/8/16 Alignment
                     • Cleartext PSK Leaks                                           • Sequence Monotonicity
                                  |                                                                 |
                                  |                                   +-----------------------------+-----------------------------+
                                  |                                   |                             |                             |
                                  |                                   v                             v                             v
                                  |                       +-----------------------+     +-----------------------+     +-----------------------+
                                  |                       |    MODE HEURISTIC     |     |   PADDING HEURISTIC   |     |   ISOLATION FOREST    |
                                  |                       |  (Tunnel vs Transport)|     | (3DES / CBC / GCM)    |     |  (Anomaly Detection)  |
                                  |                       +-----------+-----------+     +-----------+-----------+     +-----------+-----------+
                                  |                                   |                             |                             |
                                  |                                   +-----------------------------+-----------------------------+
                                  |                                                                 |
                                  |                                                                 v
                                  |                                                     +-----------------------+
                                  |                                                     |    XGBOOST AI MODEL   |
                                  |                                                     |  (8 Traffic Classes)  |
                                  |                                                     +-----------+-----------+
                                  |                                                                 |
                                  |                                                                 v
                                  |                                                      +-----------------------+
                                  |                                                      |   SHAP EXPLAINABILITY |
                                  |                                                      | (Feature Attribution) |
                                  |                                                      +-----------+-----------+
                                  |                                                                 |
                                  +-------------------------------+---------------------------------+
                                                                  |
                                                                  v
                                              +---------------------------------------+
                                              |       RISK & THREAT CORRELATION       |
                                              +-------------------+-------------------+
                                                                  |
                       +-------------------------+----------------+------------------------+-------------------------+
                       |                         |                                         |                         |
                       v                         v                                         v                         v
           +-----------------------+ +-----------------------+                 +-----------------------+ +-----------------------+
           | NIST SP 800-77 RULES  | |   MITRE ATT&CK / CVE  |                 |  CNSA 2.0 / PQC SCORE | | REMEDIATION ADVISOR   |
           | • Crypto Strength     | | • Sweet32 (CVE-2016)  |                 | • Shor's Resistance   | | • strongSwan Configs  |
           | • Key Management      | | • Logjam (CVE-2015)   |                 | • Grover's Resistance | | • Cisco IOS Configs   |
           | • Forward Secrecy     | | • Aggressive PSK Leak |                 | • HNDL Threat Index   | | • Hardening Snippets  |
           | • Metadata Exposure   | | • Transmitted Forgery |                 +-----------------------+ +-----------------------+
           | • Replay Protection   | +-----------------------+
           +-----------------------+
                                                                  |
                                  +-------------------------------+-------------------------------+
                                  |                               |                               |
                                  v                               v                               v
                     +--------------------------+   +--------------------------+   +--------------------------+
                     |    EXECUTIVE REPORT      |   |   TECHNICAL AUDIT REPORT |   | INTERACTIVE WEB DASHBOARD|
                     |     (HTML / PDF)         |   |     (HTML / PDF)         |   | (Single / Diff / Live /  |
                     +--------------------------+   +--------------------------+   |  Peer-to-Peer Tunnel)    |
                                                                                   +--------------------------+
```

---

## 3. Technical Breakdown: Live Traffic & ChatGPT Classification

### How Live Network Sniffing & ChatGPT Analysis Works

1. **Passive Interception on the Wire**:
   - The sniffer engine ([`ipsecguard/sniffer/live.py`](file:///C:/projects/IPsec/ipsecguard/sniffer/live.py)) hooks directly into local network adapters via Scapy's `AsyncSniffer`.
   - Captures live IKE negotiation (`UDP 500/4500`), ESP (`IP proto 50`), AH (`IP proto 51`), and HTTPS/TLS application flows (`TCP 443`).

2. **ChatGPT Traffic Metadata Fingerprint**:
   - **User Request (Prompt)**: Single compact upstream packet burst (~250–500 bytes).
   - **ChatGPT Response (Server-Sent Events)**: Streaming token generation delivers chunked HTTP/2 TLS frames at regular 20–50ms intervals.
   - **Padding & Encapsulation**: When transmitted over an IPsec VPN tunnel, the payload is encapsulated into ESP frames with 16-byte block alignment (AES-CBC/GCM).
   - **AI Classification**: Without decrypting the SSL/TLS or ESP payload, the XGBoost model observes the characteristic inter-arrival time (IAT), burst length, packet size distribution, and directional byte asymmetry, classifying the encrypted flow as **`web` / `mixed` / `interactive stream`** with high confidence.

---

## 4. Multi-Device Peer-to-Peer Secure IPsec VPN Architecture

### Cross-Device Tunnel & Compliance Verification
The platform includes an integrated Peer-to-Peer IPsec Node ([`ipsecguard/tunnel/peer.py`](file:///C:/projects/IPsec/ipsecguard/tunnel/peer.py)):

1. **Phase 1 (Live IKE Handshake)**:
   - Node A (e.g. Device 1) sends an authentic `IKE_SA_INIT` payload over UDP to Node B (e.g. Device 2 on local network or across the internet).
   - Users can select **Modern Secure** (`AES-256-GCM`, `DH-19`, `SHA-384`, `PFS=on`) or **Legacy Weak** (`3DES`, `DH-2`, `MD5`, `PFS=off`).

2. **Phase 2 (Child SA & ESP Tunneling)**:
   - Establishes active Security Associations (SPIs, encryption keys using real cryptographic primitives).

3. **Phase 3 (Encrypted Data Transmission)**:
   - Users can type text messages, chat, or transfer data payloads between the two website instances.
   - Packets are encapsulated into RFC 4303 ESP frames with sequence numbering and authentication tags.

4. **Phase 4 (Live Compliance Audit)**:
   - Either device can click **"Audit This Live Tunnel Session"** to pass all live captured wire packets into the analyzer and verify that the tunnel adheres to all NIST SP 800-77 & NTRO requirements.

---

## 5. Comprehensive Feature Matrix

| Capability | Problem Statement Requirement | Implementation in IPsecGuard AI | Status |
| :--- | :--- | :--- | :--- |
| **IKE Version & Proposals** | Identify IKE version & crypto transforms | Plaintext binary IKE parser ([`ipsecguard/parser/ike.py`](file:///C:/projects/IPsec/ipsecguard/parser/ike.py)) | ✅ Completed |
| **Tunnel vs. Transport Mode** | Infer VPN operating mode | Payload overhead heuristic in [`heuristics.py`](file:///C:/projects/IPsec/ipsecguard/ml/heuristics.py) | ✅ Completed |
| **Cipher Family Identification** | Identify Encryption Algorithm | Mod-8 / Mod-16 padding analysis (3DES, AES-CBC, AES-GCM) | ✅ Completed |
| **Multi-Class Traffic Classification** | Classify VoIP, WhatsApp, Email, Video, Web, ICMP, Bulk | XGBoost tree classifier trained across 8 distinct traffic profiles | ✅ **94.12% Accuracy** |
| **AI Interpretability** | AI Confidence Score & Explanation | SHAP TreeExplainer feature importance breakdown | ✅ Completed |
| **Replay Protection** | Replay protection evaluation | Sequence number monotonicity & gap frequency analyzer | ✅ Completed |
| **AH Protocol Analysis** | AH packet support | Binary IP protocol 51 parser ([`parser/ah.py`](file:///C:/projects/IPsec/ipsecguard/parser/ah.py)) | ✅ Completed |
| **IPv6 Dual-Stack Support** | IPv4 and IPv6 communication | Full dual-stack support in IKE parser & ESP extractor | ✅ Completed |
| **Live Network Sniffer** | Inspect captured traffic or live streams | Real-time packet sniffer with ChatGPT flow analysis | ✅ Completed |
| **Peer-to-Peer IPsec Tunnel** | Create connection across devices | Live multi-device UDP IPsec tunnel & audit suite | ✅ Completed |
| **Standards Compliance** | Configuration compliance | Automated checks against NIST SP 800-77 Rev. 1 & CNSA Suite | ✅ Completed |
| **Threat Intel & CVE Mapping** | Threat Matrix & Risk scoring | Correlates findings to MITRE ATT&CK (T1588, T1557, T1040) & CVEs | ✅ Completed |
| **Post-Quantum Cryptography** | Forward Secrecy & Quantum risk | PQC Readiness Index evaluating Shor's & Grover's resilience | ✅ Completed |
| **Side-by-Side Diff Mode** | Comparative assessment | `/api/compare` endpoint and visual before/after posture comparison | ✅ Completed |
| **Automated Remediation** | Actionable recommendations | Generates copy-paste configs for strongSwan & Cisco IOS | ✅ Completed |
| **Multi-Format Export** | Executive & Technical Reports | Executive & Technical HTML/PDF reports, JSON, and CSV export | ✅ Completed |
| **strongSwan Testbed** | VPN Testbed laboratory environment | Docker Compose testbed with `tcpdump` sidecar + `capture.sh` | ✅ Completed |
| **One-Click Tooling** | Working software prototype | Windows launcher (`start.bat`) and auto git sync (`sync.bat`) | ✅ Completed |

---

## 6. Machine Learning & Model Performance

### Traffic Classification Metrics
- **Model**: XGBoost Multi-Class Classifier (`XGBClassifier`)
- **Evaluation Strategy**: `GroupShuffleSplit` across 6 cryptographic configurations (evaluated on configurations **never seen during training**, preventing data leakage).
- **Metrics Summary**:
  - **Accuracy**: `94.12%`
  - **Macro F1 Score**: `0.9333`
  - **Classes (8)**: `bulk`, `email`, `icmp`, `mixed`, `video`, `voip`, `web`, `whatsapp`

---

## 7. Verification & Quality Assurance

### Automated Pytest Suite
Ran full test suite:
```text
tests\test_ah_and_ipv6.py ...                                            [ 16%]
tests\test_api.py .......                                                [ 55%]
tests\test_live_and_tunnel.py ...                                        [ 72%]
tests\test_parser.py ...                                                 [ 88%]
tests\test_scoring.py ..                                                 [100%]

======================= 18 passed in 7.12s =======================
```
**18 of 18 unit and integration tests passed.**

---

## 8. How to Demonstrate All 4 Modes

1. **Launch Dashboard**:
   Double-click [`start.bat`](file:///C:/projects/IPsec/start.bat) (or run `.\start.bat` in terminal).
   The browser opens to `http://localhost:8000`.

2. **Mode 1: Single Capture Audit**:
   - Pick any pre-built capture (e.g. `cfg0_icmp_transport_3des-family_3des_dh2_pfsoff.pcap`) and click **"Analyze Protocol"**.
   - Review NIST score, Subscores, Threat Matrix, MITRE ATT&CK CVEs, Quantum PQC index, and download Executive/Technical reports.

3. **Mode 2: Side-by-Side Diff Comparison**:
   - Click **"Side-by-Side PCAP Diff"**.
   - Select Capture A (legacy 3DES) and Capture B (modern AES-GCM).
   - Click **"Compare Captures"** to see instant security posture deltas (`+50 pts`) and resolved flaws.

4. **Mode 3: Live Sniffer & ChatGPT Flow Analysis**:
   - Click **"Live Traffic Sniffer & ChatGPT"**.
   - Click **"Start Live Sniffing"**.
   - Open ChatGPT in another browser tab and send a prompt.
   - Click **"Stop Sniffing"** and **"Analyze Live Session"** to see live flow classification and security telemetry.

5. **Mode 4: Multi-Device Peer-to-Peer IPsec VPN**:
   - On Device 1: Open dashboard ➔ Click **"Live Peer-to-Peer IPsec VPN"** ➔ Click **"Start Listening"** on port `8500`.
   - On Device 2: Enter Device 1's IP Address (e.g. `192.168.1.100`), select cipher suite (e.g. `AES-256-GCM`), and click **"Establish IPsec Tunnel"**.
   - Type messages to transmit real encrypted ESP packets over the wire.
   - Click **"Audit This Live Tunnel Session"** on either device to perform a live compliance assessment.
