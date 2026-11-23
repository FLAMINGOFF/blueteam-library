---
title: HackTool - SharpUp PrivEsc Tool Execution
summary: Detects the use of SharpUp, a tool for local privilege escalation
sigma_id: c484e533-ee16-4a93-b6ac-f0ea4868b2f1
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0004
  - TA0007
  - TA0002
techniques:
  - T1615
  - T1569.002
  - T1574.005
author: Florian Roth (Nextron Systems)
date: '2022-08-20'
modified: '2023-02-13'
falsepositives:
  - Unknown
references:
  - https://github.com/GhostPack/SharpUp
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_sharpup.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SharpUp PrivEsc Tool Execution
id: c484e533-ee16-4a93-b6ac-f0ea4868b2f1
status: test
description: Detects the use of SharpUp, a tool for local privilege escalation
references:
    - https://github.com/GhostPack/SharpUp
author: Florian Roth (Nextron Systems)
date: 2022-08-20
modified: 2023-02-13
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.discovery
    - attack.execution
    - attack.stealth
    - attack.t1615
    - attack.t1569.002
    - attack.t1574.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\SharpUp.exe'
        - Description: 'SharpUp'
        - CommandLine|contains:
              - 'HijackablePaths'
              - 'UnquotedServicePath'
              - 'ProcessDLLHijack'
              - 'ModifiableServiceBinaries'
              - 'ModifiableScheduledTask'
              - 'DomainGPPPassword'
              - 'CachedGPPPassword'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
