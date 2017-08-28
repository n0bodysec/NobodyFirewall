# What is Nobody's Firewall?
Nobody's Firewall (aka nfwall) is a simple —but powerful— firewall for SA-MP that protect your server against query flood/cookie flood attacks.

Requisites
-------------------------------
- [`libpcap`](https://github.com/the-tcpdump-group/libpcap)

## Getting Started
1. ```apt-get update && apt-get install gcc libpcap0.8* -y```
2. ```git clone https://github.com/n0bodysec/NobodyFirewall.git```
3. ```cd NobodyFirewall```
4. ```make```

## Usage
```./nfwall <iface>```

Acknowledgments
-------------------------------
* **n3ptun0 (aka Stella)** for his firewall for SA-MP 0.3e.
* **Silver Moon** for his base code.

License
-------

[GNU General Public License version 3](http://www.gnu.org/licenses/gpl.txt)

Copyright (c) 2017 Nobody

All rights reserved

Nobody's Firewall is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your discretion) any later version.

Nobody's Firewall is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Nobody's Firewall. If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/).
