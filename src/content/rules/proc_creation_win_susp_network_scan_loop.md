---
title: Suspicious Scan Loop Network
summary: Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system
sigma_id: f8ad2e2c-40b6-4117-84d7-20b89896ab23
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0007
techniques:
  - T1059
  - T1018
author: frack113
date: '2022-03-12'
falsepositives:
  - Legitimate script
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md
  - https://ss64.com/nt/for.html
  - https://ss64.com/ps/foreach-object.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_network_scan_loop.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Scan Loop Network
id: f8ad2e2c-40b6-4117-84d7-20b89896ab23
status: test
description: Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md
    - https://ss64.com/nt/for.html
    - https://ss64.com/ps/foreach-object.html
author: frack113
date: 2022-03-12
tags:
    - attack.execution
    - attack.t1059
    - attack.discovery
    - attack.t1018
logsource:
    category: process_creation
    product: windows
detection:
    selection_loop:
        CommandLine|contains:
            - 'for '
            - 'foreach '
    selection_tools:
        CommandLine|contains:
            - 'nslookup'
            - 'ping'
    condition: all of selection_*
falsepositives:
    - Legitimate script
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_susp_network_scan_loop/info.yml
```
