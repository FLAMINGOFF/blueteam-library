---
title: Remote Access Tool - AnyDesk Piped Password Via CLI
summary: Detects piping the password to an anydesk instance via CMD and the '--set-password' flag.
sigma_id: b1377339-fda6-477a-b455-ac0923f9ec2c
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219.002
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-28'
modified: '2023-03-05'
falsepositives:
  - Legitimate piping of the password to anydesk
  - Some FP could occur with similar tools that uses the same command line '--set-password'
references:
  - https://redcanary.com/blog/misbehaving-rats/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_piped_password_via_cli.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - AnyDesk Piped Password Via CLI
id: b1377339-fda6-477a-b455-ac0923f9ec2c
status: test
description: Detects piping the password to an anydesk instance via CMD and the '--set-password' flag.
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-28
modified: 2023-03-05
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            # Example: C:\WINDOWS\system32\cmd.exe /C cmd.exe /c echo J9kzQ2Y0qO |C:\ProgramData\anydesk.exe --set-password
            - '/c '
            - 'echo '
            - '.exe --set-password'
    condition: selection
falsepositives:
    - Legitimate piping of the password to anydesk
    - Some FP could occur with similar tools that uses the same command line '--set-password'
level: medium
```
