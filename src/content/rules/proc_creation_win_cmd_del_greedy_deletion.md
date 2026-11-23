---
title: Greedy File Deletion Using Del
summary: >-
  Detects execution of the "del" builtin command to remove files using greedy/wildcard expression. This is often used by malware to delete content of folders that perhaps contains the initial malware
  infection or to delete evidence.
sigma_id: 204b17ae-4007-471b-917b-b917b315c5db
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1070.004
author: frack113 , X__Junior (Nextron Systems)
date: '2021-12-02'
modified: '2023-09-11'
falsepositives:
  - Unknown
references:
  - https://www.joesandbox.com/analysis/509330/0/html#1044F3BDBE3BB6F734E357235F4D5898582D
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/erase
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_cmd_del_greedy_deletion.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Greedy File Deletion Using Del
id: 204b17ae-4007-471b-917b-b917b315c5db
status: test
description: Detects execution of the "del" builtin command to remove files using greedy/wildcard expression. This is often used by malware to delete content of folders that perhaps contains the initial malware infection or to delete evidence.
references:
    - https://www.joesandbox.com/analysis/509330/0/html#1044F3BDBE3BB6F734E357235F4D5898582D
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/erase
author: frack113 , X__Junior (Nextron Systems)
date: 2021-12-02
modified: 2023-09-11
tags:
    - attack.stealth
    - attack.t1070.004
logsource:
    category: process_creation
    product: windows
detection:
    # Example:
    #   del C:\ProgramData\*.dll & exit
    selection_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_del:
        CommandLine|contains:
            - 'del '
            - 'erase '
    selection_extensions:
        CommandLine|contains:
            - '\\\*.au3'
            - '\\\*.dll'
            - '\\\*.exe'
            - '\\\*.js'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
