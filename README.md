# UniFi Dynamic IP Whitelisting Server

This Python + Flask app allows remote devices to register their public IP address and automatically update a UniFi firewall group for secure remote access.

## 🔧 Features
- Webhook server to receive IPs securely
- Immediate sync to UniFi firewall group
- Automatic expiration of old IPs (default: 24h)
- Docker + Docker Compose support

## 🚀 Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/your-username/unifi-ip-sync.git
cd unifi-ip-sync
