---
title: Indirect Command Execution From Script File Via Bash.EXE
summary: |-
  Detects execution of Microsoft bash launcher without any flags to execute the content of a bash script directly.
  This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash.
sigma_id: 2d22a514-e024-4428-9dba-41505bd63a5b
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1202
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-08-15'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Bash/
  - https://linux.die.net/man/1/bash
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_bash_file_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Indirect Command Execution From Script File Via Bash.EXE
id: 2d22a514-e024-4428-9dba-41505bd63a5b
related:
    - id: 5edc2273-c26f-406c-83f3-f4d948e740dd
      type: similar
status: test
description: |
    Detects execution of Microsoft bash launcher without any flags to execute the content of a bash script directly.
    This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Bash/
    - https://linux.die.net/man/1/bash
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-15
tags:
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - ':\Windows\System32\bash.exe'
              - ':\Windows\SysWOW64\bash.exe'
        - OriginalFileName: 'Bash.exe'
    filter_main_cli_flag:
        CommandLine|contains:
            # Note: we're not interested in flags being passed first
            - 'bash.exe -'
            - 'bash -'
    filter_main_no_cli:
        CommandLine: null
    filter_main_empty:
        CommandLine: ''
    filter_main_no_flag:
        CommandLine:
            - 'bash.exe'
            - 'bash'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
