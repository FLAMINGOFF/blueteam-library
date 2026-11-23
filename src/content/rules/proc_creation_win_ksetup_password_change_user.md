---
title: Logged-On User Password Change Via Ksetup.EXE
summary: Detects password change for the logged-on user's via "ksetup.exe"
sigma_id: c9783e20-4793-4164-ba96-d9ee483992c4
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-04-06'
falsepositives:
  - Unknown
references:
  - https://learn.microsoft.com/en-gb/windows-server/administration/windows-commands/ksetup
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ksetup_password_change_user.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Logged-On User Password Change Via Ksetup.EXE
id: c9783e20-4793-4164-ba96-d9ee483992c4
status: test
description: Detects password change for the logged-on user's via "ksetup.exe"
references:
    - https://learn.microsoft.com/en-gb/windows-server/administration/windows-commands/ksetup
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-04-06
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\ksetup.exe'
        - OriginalFileName: 'ksetup.exe'
    selection_cli:
        CommandLine|contains: ' /ChangePassword '
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
