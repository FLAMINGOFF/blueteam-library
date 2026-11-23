---
title: Suspicious Query of MachineGUID
summary: Use of reg to get MachineGuid information
sigma_id: f5240972-3938-4e56-8e4b-e33893176c1f
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1082
author: frack113
date: '2022-01-01'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-8---windows-machineguid-discovery
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_machineguid.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Query of MachineGUID
id: f5240972-3938-4e56-8e4b-e33893176c1f
status: test
description: Use of reg to get MachineGuid information
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-8---windows-machineguid-discovery
author: frack113
date: 2022-01-01
tags:
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains|all:
            - 'SOFTWARE\Microsoft\Cryptography'
            - '/v '
            - 'MachineGuid'
    condition: selection
falsepositives:
    - Unknown
level: low
```
