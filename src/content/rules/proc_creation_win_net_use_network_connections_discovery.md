---
title: System Network Connections Discovery Via Net.EXE
summary: Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.
sigma_id: 1c67a717-32ba-409b-a45d-0fb704a73a81
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1049
author: frack113
date: '2021-12-10'
modified: '2023-02-21'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md#atomic-test-1---system-network-connections-discovery
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_net_use_network_connections_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: System Network Connections Discovery Via Net.EXE
id: 1c67a717-32ba-409b-a45d-0fb704a73a81
status: test
description: Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md#atomic-test-1---system-network-connections-discovery
author: frack113
date: 2021-12-10
modified: 2023-02-21
tags:
    - attack.discovery
    - attack.t1049
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
    selection_cli:
        - CommandLine|endswith:
              - ' use'
              - ' sessions'
        - CommandLine|contains:
              - ' use '
              - ' sessions '
    condition: all of selection_*
falsepositives:
    - Unknown
level: low
```
