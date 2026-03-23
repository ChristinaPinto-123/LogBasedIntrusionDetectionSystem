# Custom Log-Based Intrusion Detection System
A lightweight Python-based security tool designed to monitor Linux authentication logs in real-time, detect SSH brute-force patterns, and forward structured alerts to a SIEM (Security Information and Event Management) system.

**🛠 Features**
- Pattern Extraction: Utilizes Regular Expressions (Regex) to parse Source IP and Target Username from failed login attempts.
- Sliding Window Detection: Tracks failure frequency within a configurable time window (e.g., 2 failures in 120 seconds).
- Real-Time Discord Notifications: Integrated with Discord Webhooks to send instant push notifications to a security channel when an attack is detected.
- Cloud-Native Deployment: Fully tested and deployed on Azure Ubuntu 24.04 LTS, monitoring live traffic on a public-facing IPv4 address.
