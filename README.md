🛡️ ZETROS: Zero-Trust IoT Security Framework
PUF-Based Authentication | ML Trust Scoring | Blockchain Blacklisting

This repository contains the integrated ZETROS framework. It uses Physical Unclonable Functions (PUF) for hardware-bound authentication, Machine Learning for behavioral anomaly detection, and Blockchain for a distributed device blacklist.

📂 Project Structure
client_iot/: Our custom PUF-based device logic (Phase 1 & 2).

server_hub/: The central hub that handles registration and authentication.

common/: Shared cryptographic and encoding utilities.

authority_ca/: Simulated Certificate Authority for MSG3/MSG4 verification.

ml/: (Friend A) Machine Learning models for trust scoring.

server/ & client/: (Skeleton) Integration placeholders.

data/: Shared folder for traffic_data.csv (ML input) and databases.

🛠️ Prerequisites
Ensure you have Python 3.10+ installed. Install the required cryptographic libraries:

Bash
pip install cryptography
🔑 Setup: Generating Security Keys
Before running the system, you must generate your own RSA keys and CA certificates.

Generate Server Keys:
Run the key generator script inside server_hub:

Bash
python3 -m server_hub.server_keys
This will create server_private.pem and server_public.pem in your root directory.

CA Setup:
Ensure authority_ca/ca_keys.py exists (this handles the MSG3/4 simulation).

🚀 Execution Flow
1. Start the Hub (The Server)
The Hub must be running to listen for registration and connection requests. It will also start logging traffic to traffic_data.csv for the ML module.

Bash
python3 -m server_hub.hub
2. Run the Device (Phase 1: Registration)
If the device has never registered before (no device_vault.json exists), running this command will trigger the 9-step ZETROS registration.

Bash
python3 -m client_iot.device
Result: A device_vault.json is created locally, and the Hub saves the hardware fingerprint to puf_database.json.

3. Run the Device (Phase 2: Authentication)
Run the same command again. The device will now detect the vault and perform a quick 4-step hardware-challenge handshake.

Bash
python3 -m client_iot.device
Result: You should see ✅ [AUTH SUCCESS] on the terminal if the PUF response matches the database.

📊 Integration for Team Members
🧠 ML Friend (Trust Scoring)
The Hub automatically logs all inbound and outbound traffic to traffic_data.csv.

Task: Use ml/train.py to train on the provided dataset and ml/model.py to calculate trust scores based on the real-time CSV updates.

⛓️ Blockchain Friend (Blacklisting)
The identity of every verified device is a UUID.

Task: Implement the web3.py logic in server/blockchain.py. The Hub will call your is_blacklisted(client_id) function before allowing a Phase 2 connection.

⚠️ Security Notes
DO NOT push your .pem files or device_vault.json to GitHub. They are ignored by .gitignore.

If you get a Physical Fingerprint Mismatch, delete both puf_database.json and device_vault.json to perform a clean re-registration.