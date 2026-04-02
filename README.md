# 🛡️ ZETROS: Zero-Trust IoT Security Framework
### **PUF-Based Auth | ML Behavioral Guard | Blockchain Blacklisting**

ZETROS is a multi-layered security framework designed to protect IoT networks. It moves beyond simple passwords by verifying the **physical DNA** of the hardware (PUF) and monitoring the **behavioral rhythm** of the traffic (ML).

---

## 🏗️ System Architecture

* **Physical Layer:** Uses **Physical Unclonable Functions (PUF)** to generate unique, non-clonable hardware fingerprints.
* **Network Layer:** Implements a **4-Step Handshake** with RSA-2048 encryption, AES-GCM session keys, and **Replay Protection** (Nonces + Timestamps).
* **Intelligence Layer:** A **Random Forest IDS** trained on the **UNSW-NB15** dataset monitors traffic for DDoS, Flooding, and Anomalies.
* **Trust Layer:** (In Progress) A **Blockchain-based Ledger** to permanently blacklist malicious device IDs.

---

## 📂 Project Structure

* `client_iot/`: Device-side logic for Registration (Phase 1) and Connection (Phase 2).
* `server_hub/`: The central "Bouncer." Handles authentication and runs the ML Watchdog.
* `ml_sahil/`: **(Sahil's Module)** Contains `model.pkl`, `train.py`, and the feature extraction logic.
* `authority_ca/`: Simulated Certificate Authority for verifying Hub identity.
* `common/`: Shared cryptographic utilities (RSA, AES, XOR, Entropy).
* `data_sahil/`: The "Evidence Locker" containing `traffic_data.csv` and `puf_database.json`.

---

## 🛠️ Prerequisites & Setup

1.  **Install Dependencies:**
    ```bash
    pip install cryptography pandas scikit-learn joblib numpy
    ```

2.  **Generate Security Keys:**
    You must generate a unique "Identity" for your Hub before starting.
    ```bash
    python3 -m server_hub.server_keys
    ```

3.  **Train the ML Brain:**
    Ensure the model is compatible with your local environment.
    ```bash
    python3 ml_sahil/train.py
    ```

---

## 🚀 Execution Flow

### **Step 1: Start the Hub**
The Hub acts as the central gateway. It listens for devices and runs the ML behavioral analysis in the background.
```bash
python3 -m server_hub.hub
```

### **Step 2: Device Registration (Phase 1)**
If a device is new, it must register its PUF fingerprint.
```bash
python3 -m client_iot.device
```
*Result: `device_vault.json` is created on the device; hardware hash is stored in the Hub's DB.*

### **Step 3: Secure Connection (Phase 2)**
Run the device again to perform the 4-step hardware-bound handshake.
```bash
python3 -m client_iot.device
```
*Result: Hub verifies the physical fingerprint. `✅ [AUTH SUCCESS]`*

---

## 🧪 Testing & Attack Simulation

### **The "Chaos Test" (DDoS Simulation)**
To verify the ML Watchdog is working, run the chaos engine. It will attempt to flood the Hub with high-frequency requests.
```bash
python3 attack_chaos.py
```
**Expected Hub Output:**
* `ATTACK PROB: 0.88+`
* `🚨 [ML ALERT] Anomaly detected from 127.0.0.1! High probability of attack.`

### **Replay Protection Test**
Attempting to send the same packet twice or sending a packet with an old timestamp will be caught by the Hub's Replay Gatekeeper.
* **Result:** `🚫 [REPLAY] CONN1 blocked.`

---

## 📊 Feature Mapping (For ML Development)
The Hub logs raw data to `traffic_data.csv`. The ML module aggregates these into **5 UNSW-NB15 features**:

| Feature | Logic | Purpose |
| :--- | :--- | :--- |
| **Requests/Sec** | Packets over Window Time | Detects Flooding/DDoS |
| **Avg Interval** | Time between packets | Detects scripted/bot behavior |
| **Bytes/Sec** | Data volume over time | Detects data exfiltration |
| **Avg Packet Size** | Total Bytes / Total Packets | Detects standard attack signatures |
| **Packet Ratio** | Inbound vs Outbound | Detects scanning/one-way floods |

---

## ⚠️ Security Warning
* **Vault Security:** `device_vault.json` contains your PUF seed. **Never share it.**
* **Private Keys:** `server_private.pem` should never be pushed to GitHub (already in `.gitignore`).
* **Database Reset:** If you change your RSA keys, delete `puf_database.json` and `device_vault.json` to start a clean registration.

---