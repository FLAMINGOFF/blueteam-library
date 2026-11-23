---
title: PUA - Wsudo Suspicious Execution
summary: Detects usage of wsudo (Windows Sudo Utility). Which is a tool that let the user execute programs with different permissions (System, Trusted Installer, Administrator...etc)
sigma_id: bdeeabc9-ff2a-4a51-be59-bb253aac7891
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0004
techniques:
  - T1059
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-12-02'
modified: '2023-02-14'
falsepositives:
  - Unknown
references:
  - https://github.com/M2Team/Privexec/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_wsudo_susp_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - Wsudo Suspicious Execution
id: bdeeabc9-ff2a-4a51-be59-bb253aac7891
status: test
description: Detects usage of wsudo (Windows Sudo Utility). Which is a tool that let the user execute programs with different permissions (System, Trusted Installer, Administrator...etc)
references:
    - https://github.com/M2Team/Privexec/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-02
modified: 2023-02-14
tags:
    - attack.execution
    - attack.privilege-escalation
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_metadata:
        - Image|endswith: '\wsudo.exe'
        - OriginalFileName: 'wsudo.exe'
        - Description: 'Windows sudo utility'
        - ParentImage|endswith: '\wsudo-bridge.exe'
    selection_cli:
        CommandLine|contains:
            - '-u System'
            - '-uSystem'
            - '-u TrustedInstaller'
            - '-uTrustedInstaller'
            - ' --ti '
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
```
