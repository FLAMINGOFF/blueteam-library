---
title: Computer Password Change Via Ksetup.EXE
summary: Detects password change for the computer's domain account or host principal via "ksetup.exe"
sigma_id: de16d92c-c446-4d53-8938-10aeef41c8b6
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
  - https://twitter.com/Oddvarmoe/status/1641712700605513729
  - https://learn.microsoft.com/en-gb/windows-server/administration/windows-commands/ksetup
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ksetup_password_change_computer.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Computer Password Change Via Ksetup.EXE
id: de16d92c-c446-4d53-8938-10aeef41c8b6
status: test
description: Detects password change for the computer's domain account or host principal via "ksetup.exe"
references:
    - https://twitter.com/Oddvarmoe/status/1641712700605513729
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
        CommandLine|contains: ' /setcomputerpassword '
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
