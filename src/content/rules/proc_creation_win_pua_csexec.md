---
title: PUA - CsExec Execution
summary: Detects the use of the lesser known remote execution tool named CsExec a PsExec alternative
sigma_id: d08a2711-ee8b-4323-bdec-b7d85e892b31
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0042
  - TA0002
techniques:
  - T1587.001
  - T1569.002
author: Florian Roth (Nextron Systems)
date: '2022-08-22'
modified: '2023-02-21'
falsepositives:
  - Unknown
references:
  - https://github.com/malcomvetter/CSExec
  - https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_csexec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - CsExec Execution
id: d08a2711-ee8b-4323-bdec-b7d85e892b31
status: test
description: Detects the use of the lesser known remote execution tool named CsExec a PsExec alternative
references:
    - https://github.com/malcomvetter/CSExec
    - https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/
author: Florian Roth (Nextron Systems)
date: 2022-08-22
modified: 2023-02-21
tags:
    - attack.resource-development
    - attack.t1587.001
    - attack.execution
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\csexec.exe'
    selection_pe:
        Description: 'csexec'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
```
