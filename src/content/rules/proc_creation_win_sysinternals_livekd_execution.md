---
title: Potential Memory Dumping Activity Via LiveKD
summary: Detects execution of LiveKD based on PE metadata or image name
sigma_id: a85f7765-698a-4088-afa0-ecfbf8d01fa4
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-05-15'
falsepositives:
  - Administration and debugging activity (must be investigated)
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_livekd_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Memory Dumping Activity Via LiveKD
id: a85f7765-698a-4088-afa0-ecfbf8d01fa4
status: test
description: Detects execution of LiveKD based on PE metadata or image name
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-15
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\livekd.exe'
              - '\livekd64.exe'
        - OriginalFileName: 'livekd.exe'
    condition: selection
falsepositives:
    - Administration and debugging activity (must be investigated)
level: medium
```
