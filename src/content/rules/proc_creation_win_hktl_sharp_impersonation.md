---
title: HackTool - SharpImpersonation Execution
summary: Detects execution of the SharpImpersonation tool. Which can be used to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively
sigma_id: f89b08d0-77ad-4728-817b-9b16c5a69c7a
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0005
techniques:
  - T1134.001
  - T1134.003
author: Sai Prashanth Pulisetti @pulisettis, Nasreddine Bencherchali (Nextron Systems)
date: '2022-12-27'
modified: '2023-02-13'
falsepositives:
  - Unknown
references:
  - https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/
  - https://github.com/S3cur3Th1sSh1t/SharpImpersonation
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_sharp_impersonation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SharpImpersonation Execution
id: f89b08d0-77ad-4728-817b-9b16c5a69c7a
related:
    - id: cf0c254b-22f1-4b2b-8221-e137b3c0af94
      type: similar
status: test
description: Detects execution of the SharpImpersonation tool. Which can be used to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively
references:
    - https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/
    - https://github.com/S3cur3Th1sSh1t/SharpImpersonation
author: Sai Prashanth Pulisetti @pulisettis, Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-27
modified: 2023-02-13
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1134.001
    - attack.t1134.003
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\SharpImpersonation.exe'
        - OriginalFileName: 'SharpImpersonation.exe'
    selection_cli:
        - CommandLine|contains|all:
              - ' user:'
              - ' binary:'
        - CommandLine|contains|all:
              - ' user:'
              - ' shellcode:'
        - CommandLine|contains:
              - ' technique:CreateProcessAsUserW'
              - ' technique:ImpersonateLoggedOnuser'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
```
