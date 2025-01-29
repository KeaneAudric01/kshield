# kshield 🚀

kshield is a comprehensive iptables-based firewall script designed to enhance the security of your server by applying various rules and protections.

## Disclaimer ⚠️

Use this script at your own risk. Ensure you understand the rules being applied and test in a safe environment before deploying to production.

## Features ✨

- Flush existing iptables rules
- Drop bogon source IPs
- Block unusual TCP flags
- Enable SYNPROXY for SYN flood protection
- Comprehensive logging
- Allow specific traffic (SSH, HTTP, HTTPS)
- Rate limiting and connection limits
- Protection against various amplification attacks
- Enhanced SYN flood protection
- Global rate limit for inbound UDP
- Port scanning protection
- ICMP flood protection

## Usage 📋

To use the `kshield.sh` script, follow these steps:

1. Download the script to your server.
2. Make the script executable:

    ```sh
    chmod +x kshield.sh
    ```

3. Run the script with sudo:

    ```sh
    sudo ./kshield.sh
    ```

### Example Commands

- Run the script to apply the firewall rules:

    ```sh
    sudo ./kshield.sh
    ```

## Installation 🛠️

### Prerequisites

- A server running Ubuntu 24.04

### Setting Up the Firewall

1. Update your package list:

    ```sh
    sudo apt update
    sudo apt upgrade
    ```

2. Install `iptables` and `netfilter-persistent`:

    ```sh
    sudo apt install iptables-persistent netfilter-persistent
    ```

3. Download the `kshield.sh` script to your server.
4. Make the script executable:

    ```sh
    chmod +x kshield.sh
    ```

5. Run the script with sudo:

    ```sh
    sudo ./kshield.sh
    ```

6. Save the iptables rules to be persistent across reboots:

    ```sh
    sudo netfilter-persistent save
    ```

7. Reload the iptables rules:

    ```sh
    sudo netfilter-persistent reload
    ```

8. To restart the iptables service:

    ```sh
    sudo systemctl restart netfilter-persistent
    ```

## License 📄

This project is licensed under the MIT License. See the [LICENSE](https://github.com/KeaneAudric01/kshield/blob/main/LICENSE) file for details.

## Author 👤

Keane Audric

GitHub: [KeaneAudric01](https://github.com/KeaneAudric01)