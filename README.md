# 🚀 OhMySNI

**OhMySNI** is a C++ based network utility designed to detect SNI (Server Name Indication) data in HTTPS traffic and mitigate DPI (Deep Packet Inspection) censorship by strategically fragmenting TCP packets.

## 🛠 Features
- **Real-time SNI Analysis:** Intercepts outgoing packets and inspects the destination domain.
- **TCP Segmentation:** Splits packets at critical offsets to bypass censorship firewalls.
- **Dynamic Domain Management:** Uses `sites.csv` for an instantly updateable target list.
- **Automatic Cleanup:** Built-in `trap` mechanism in the shell script to reset `iptables` rules on exit.

## 📋 Prerequisites
To compile and run this project, you need the Linux kernel development libraries:
```bash
sudo apt-get update
sudo apt-get install libnetfilter-queue-dev g++ iptables
```

> **Note:** This application is just running on Linux