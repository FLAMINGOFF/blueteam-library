---
title: Potential Arbitrary Command Execution Via FTP.EXE
summary: Detects execution of "ftp.exe" script with the "-s" or "/s" flag and any child processes ran by "ftp.exe".
sigma_id: 06b401f4-107c-4ff9-947f-9ec1e7649f1e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
  - T1202
author: Victor Sergeev, oscd.community
date: '2020-10-09'
modified: '2024-04-23'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Ftp/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ftp_arbitrary_command_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Arbitrary Command Execution Via FTP.EXE
id: 06b401f4-107c-4ff9-947f-9ec1e7649f1e
status: test
description: Detects execution of "ftp.exe" script with the "-s" or "/s" flag and any child processes ran by "ftp.exe".
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Ftp/
author: Victor Sergeev, oscd.community
date: 2020-10-09
modified: 2024-04-23
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\ftp.exe'
    selection_child_img:
        - Image|endswith: '\ftp.exe'
        - OriginalFileName: 'ftp.exe'
    selection_child_cli:
        CommandLine|contains|windash: '-s:'
    condition: selection_parent or all of selection_child_*
falsepositives:
    - Unknown
level: medium
```
