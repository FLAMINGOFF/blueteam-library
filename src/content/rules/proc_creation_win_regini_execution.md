---
title: Registry Modification Via Regini.EXE
summary: Detects the execution of regini.exe which can be used to modify registry keys, the changes are imported from one or more text files.
sigma_id: 5f60740a-f57b-4e76-82a1-15b6ff2cb134
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
techniques:
  - T1112
author: Eli Salem, Sander Wiebing, oscd.community
date: '2020-10-08'
modified: '2023-02-08'
falsepositives:
  - Legitimate modification of keys
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Regini/
  - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regini
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_regini_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Registry Modification Via Regini.EXE
id: 5f60740a-f57b-4e76-82a1-15b6ff2cb134
related:
    - id: 77946e79-97f1-45a2-84b4-f37b5c0d8682
      type: derived
status: test
description: Detects the execution of regini.exe which can be used to modify registry keys, the changes are imported from one or more text files.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Regini/
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regini
author: Eli Salem, Sander Wiebing, oscd.community
date: 2020-10-08
modified: 2023-02-08
tags:
    - attack.persistence
    - attack.defense-impairment
    - attack.t1112
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\regini.exe'
        - OriginalFileName: 'REGINI.EXE'
    filter:
        CommandLine|re: ':[^ \\]' # Covered in 77946e79-97f1-45a2-84b4-f37b5c0d8682
    condition: selection and not filter
falsepositives:
    - Legitimate modification of keys
level: low
```
