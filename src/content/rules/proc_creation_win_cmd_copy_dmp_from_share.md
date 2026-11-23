---
title: Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE
summary: Detects usage of the copy builtin cmd command to copy files with the ".dmp"/".dump" extension from a remote share
sigma_id: 044ba588-dff4-4918-9808-3f95e8160606
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-27'
modified: '2023-09-12'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_cmd_copy_dmp_from_share.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE
id: 044ba588-dff4-4918-9808-3f95e8160606
status: test
description: Detects usage of the copy builtin cmd command to copy files with the ".dmp"/".dump" extension from a remote share
references:
    - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-27
modified: 2023-09-12
tags:
    - attack.credential-access
logsource:
    category: process_creation
    product: windows
detection:
    # Example: copy \\<host>\\<folder>\\process.dmp C:\Users\process.dmp
    selection_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_cli:
        CommandLine|contains|all:
            - 'copy '
            - ' \\\\'
        CommandLine|contains:
            - '.dmp'
            - '.dump'
            - '.hdmp'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
