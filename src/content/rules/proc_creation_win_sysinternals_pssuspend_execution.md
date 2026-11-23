---
title: Sysinternals PsSuspend Execution
summary: Detects usage of Sysinternals PsSuspend which can be abused to suspend critical processes
sigma_id: 48bbc537-b652-4b4e-bd1d-281172df448f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0007
  - TA0003
techniques:
  - T1543.003
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-03-23'
modified: '2026-06-29'
falsepositives:
  - Unknown
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/pssuspend
  - https://twitter.com/0gtweet/status/1638069413717975046
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_pssuspend_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Sysinternals PsSuspend Execution
id: 48bbc537-b652-4b4e-bd1d-281172df448f
related:
    - id: 4beb6ae0-f85b-41e2-8f18-8668abc8af78
      type: similar
status: test
description: Detects usage of Sysinternals PsSuspend which can be abused to suspend critical processes
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/pssuspend
    - https://twitter.com/0gtweet/status/1638069413717975046
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-23
modified: 2026-06-29
tags:
    - attack.privilege-escalation
    - attack.discovery
    - attack.persistence
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - OriginalFileName: 'pssuspend.exe'
        - Image|endswith:
              - '\pssuspend.exe'
              - '\pssuspend64.exe'
              - '\pssuspend64a.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
