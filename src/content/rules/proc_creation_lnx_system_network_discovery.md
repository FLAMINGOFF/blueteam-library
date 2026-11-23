---
title: System Network Discovery - Linux
summary: Detects enumeration of local network configuration
sigma_id: e7bd1cfa-b446-4c88-8afb-403bcd79e3fa
status: test
level: informational
platform: linux
logsource: linux / process_creation
tactics:
  - TA0007
techniques:
  - T1016
author: Ömer Günal and remotephone, oscd.community
date: '2020-10-06'
modified: '2022-09-15'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_system_network_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: System Network Discovery - Linux
id: e7bd1cfa-b446-4c88-8afb-403bcd79e3fa
status: test
description: Detects enumeration of local network configuration
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md
author: Ömer Günal and remotephone, oscd.community
date: 2020-10-06
modified: 2022-09-15
tags:
    - attack.discovery
    - attack.t1016
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/firewall-cmd'
            - '/ufw'
            - '/iptables'
            - '/netstat'
            - '/ss'
            - '/ip'
            - '/ifconfig'
            - '/systemd-resolve'
            - '/route'
    selection_cli:
        CommandLine|contains: '/etc/resolv.conf'
    condition: 1 of selection_*
falsepositives:
    - Legitimate administration activities
level: informational
```
