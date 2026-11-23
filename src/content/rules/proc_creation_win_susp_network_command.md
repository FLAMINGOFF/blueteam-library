---
title: Suspicious Network Command
summary: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
sigma_id: a29c1813-ab1f-4dde-b489-330b952e91ae
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1016
author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
date: '2021-12-07'
modified: '2025-10-19'
falsepositives:
  - Administrator, hotline ask to user
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md#atomic-test-1---system-network-configuration-discovery-on-windows
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_network_command.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Network Command
id: a29c1813-ab1f-4dde-b489-330b952e91ae
status: test
description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md#atomic-test-1---system-network-configuration-discovery-on-windows
author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
date: 2021-12-07
modified: 2025-10-19
tags:
    - attack.discovery
    - attack.t1016
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|re:
            - 'ipconfig\s+/all'
            - 'netsh\s+interface show interface'
            - 'arp\s+-a'
            - 'nbtstat\s+-n'
            - 'net\s+config'
            - 'route\s+print'
    condition: selection
falsepositives:
    - Administrator, hotline ask to user
level: low
```
