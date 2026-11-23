---
title: Potential Network Sniffing Activity Using Network Tools
summary: |-
  Detects potential network sniffing via use of network tools such as "tshark", "windump".
  Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection.
  An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
sigma_id: ba1f7802-adc7-48b4-9ecb-81e227fddfd5
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
  - TA0007
techniques:
  - T1040
author: Timur Zinniatullin, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: '2019-10-21'
modified: '2023-02-20'
falsepositives:
  - Legitimate administration activity to troubleshoot network issues
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1040/T1040.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_network_sniffing.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Network Sniffing Activity Using Network Tools
id: ba1f7802-adc7-48b4-9ecb-81e227fddfd5
status: test
description: |
    Detects potential network sniffing via use of network tools such as "tshark", "windump".
    Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection.
    An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1040/T1040.md
author: Timur Zinniatullin, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019-10-21
modified: 2023-02-20
tags:
    - attack.credential-access
    - attack.discovery
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection_tshark:
        Image|endswith: '\tshark.exe'
        CommandLine|contains: '-i'
    selection_windump:
        Image|endswith: '\windump.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate administration activity to troubleshoot network issues
level: medium
```
