---
title: Indirect Inline Command Execution Via Bash.EXE
summary: |-
  Detects execution of Microsoft bash launcher with the "-c" flag.
  This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash.
sigma_id: 5edc2273-c26f-406c-83f3-f4d948e740dd
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1202
author: frack113
date: '2021-11-24'
modified: '2023-08-15'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Bash/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_bash_command_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Indirect Inline Command Execution Via Bash.EXE
id: 5edc2273-c26f-406c-83f3-f4d948e740dd
related:
    - id: 2d22a514-e024-4428-9dba-41505bd63a5b
      type: similar
status: test
description: |
    Detects execution of Microsoft bash launcher with the "-c" flag.
    This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Bash/
author: frack113
date: 2021-11-24
modified: 2023-08-15
tags:
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - ':\Windows\System32\bash.exe'
              - ':\Windows\SysWOW64\bash.exe'
        - OriginalFileName: 'Bash.exe'
    selection_cli:
        CommandLine|contains: ' -c '
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
