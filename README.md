### PyFirewall

#### A simple firewall with cross platform support.

#### Features:
- Block IPs
- Block Ports


#### Requirements:
- Python 3.6+
- Windows, Linux
- Admin Privileges
- Python Libraries:
  - os
  - scapy
  - subprocess
  - platform
  - pydivert (for windows)
  - socket
  - ipaddress
  - rich


#### Installation:
- Install requirements using pip:
```bash
pip install -e .
```

- For windows you need to run the script on elevated privileges (as admin) to use the pydivert library.
- For Linux you need to run the script on elevated privileges (as root) to use the iptables command.

```bash
python3 main.py
``` 


#### Credits

Made with ❤️ by [Zaeem20](https;//github.com/Zaeem20)