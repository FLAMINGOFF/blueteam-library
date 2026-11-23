---
title: UAC Bypass Using IDiagnostic Profile
summary: Detects the "IDiagnosticProfileUAC" UAC bypass technique
sigma_id: 4cbef972-f347-4170-b62a-8253f6168e6d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0004
techniques:
  - T1548.002
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-07-03'
modified: '2024-12-01'
falsepositives:
  - Unknown
references:
  - https://github.com/Wh04m1001/IDiagnosticProfileUAC
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_uac_bypass_idiagnostic_profile.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: UAC Bypass Using IDiagnostic Profile
id: 4cbef972-f347-4170-b62a-8253f6168e6d
status: test
description: Detects the "IDiagnosticProfileUAC" UAC bypass technique
references:
    - https://github.com/Wh04m1001/IDiagnosticProfileUAC
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-03
modified: 2024-12-01
tags:
    - attack.execution
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\DllHost.exe'
        ParentCommandLine|contains: ' /Processid:{12C21EA7-2EB8-4B55-9249-AC243DA8C666}'
        IntegrityLevel:
            - 'High'
            - 'System'
            - 'S-1-16-16384' # System
            - 'S-1-16-12288' # High
    condition: selection
falsepositives:
    - Unknown
level: high
```
