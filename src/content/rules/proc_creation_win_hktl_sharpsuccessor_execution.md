---
title: HKTL - SharpSuccessor Privilege Escalation Tool Execution
summary: |-
  Detects the execution of SharpSuccessor, a tool used to exploit the BadSuccessor attack for privilege escalation in WinServer 2025 Active Directory environments.
  Successful usage of this tool can let the attackers gain the domain admin privileges by exploiting the BadSuccessor vulnerability.
sigma_id: 38a1ac5f-9c74-47d2-a345-dd6f5eb4e7c8
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1068
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-06-06'
falsepositives:
  - Unknown
references:
  - https://github.com/logangoins/SharpSuccessor
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_sharpsuccessor_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HKTL - SharpSuccessor Privilege Escalation Tool Execution
id: 38a1ac5f-9c74-47d2-a345-dd6f5eb4e7c8
status: experimental
description: |
    Detects the execution of SharpSuccessor, a tool used to exploit the BadSuccessor attack for privilege escalation in WinServer 2025 Active Directory environments.
    Successful usage of this tool can let the attackers gain the domain admin privileges by exploiting the BadSuccessor vulnerability.
references:
    - https://github.com/logangoins/SharpSuccessor
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-06-06
tags:
    - attack.privilege-escalation
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\SharpSuccessor.exe'
        - OriginalFileName: 'SharpSuccessor.exe'
        - CommandLine|contains: 'SharpSuccessor'
        - CommandLine|contains|all:
              - ' add '
              - ' /impersonate'
              - ' /path'
              - ' /account'
              - ' /name'
    condition: selection
falsepositives:
    - Unknown
level: high
```
