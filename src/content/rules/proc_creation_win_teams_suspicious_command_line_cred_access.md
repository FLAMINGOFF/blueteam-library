---
title: Potentially Suspicious Command Targeting Teams Sensitive Files
summary: |-
  Detects a commandline containing references to the Microsoft Teams database or cookies files from a process other than Teams.
  The database might contain authentication tokens and other sensitive information about the logged in accounts.
sigma_id: d2eb17db-1d39-41dc-b57f-301f6512fa75
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1528
author: '@SerkinValery'
date: '2022-09-16'
modified: '2023-12-18'
falsepositives:
  - Unknown
references:
  - https://www.bleepingcomputer.com/news/security/microsoft-teams-stores-auth-tokens-as-cleartext-in-windows-linux-macs/
  - https://www.vectra.ai/blogpost/undermining-microsoft-teams-security-by-mining-tokens
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_teams_suspicious_command_line_cred_access.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potentially Suspicious Command Targeting Teams Sensitive Files
id: d2eb17db-1d39-41dc-b57f-301f6512fa75
status: test
description: |
    Detects a commandline containing references to the Microsoft Teams database or cookies files from a process other than Teams.
    The database might contain authentication tokens and other sensitive information about the logged in accounts.
references:
    - https://www.bleepingcomputer.com/news/security/microsoft-teams-stores-auth-tokens-as-cleartext-in-windows-linux-macs/
    - https://www.vectra.ai/blogpost/undermining-microsoft-teams-security-by-mining-tokens
author: '@SerkinValery'
date: 2022-09-16
modified: 2023-12-18
tags:
    - attack.credential-access
    - attack.t1528
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '\Microsoft\Teams\Cookies'
            - '\Microsoft\Teams\Local Storage\leveldb'
    filter_main_legit_locations:
        Image|endswith: '\Microsoft\Teams\current\Teams.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
