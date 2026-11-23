---
title: Hidden Powershell in Link File Pattern
summary: Detects events that appear when a user click on a link file with a powershell command in it
sigma_id: 30e92f50-bb5a-4884-98b5-d20aa80f3d7a
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
author: frack113
date: '2022-02-06'
falsepositives:
  - Legitimate commands in .lnk files
references:
  - https://www.x86matthew.com/view_post?id=embed_exe_lnk
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_embed_exe_lnk.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Hidden Powershell in Link File Pattern
id: 30e92f50-bb5a-4884-98b5-d20aa80f3d7a
status: test
description: Detects events that appear when a user click on a link file with a powershell command in it
references:
    - https://www.x86matthew.com/view_post?id=embed_exe_lnk
author: frack113
date: 2022-02-06
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: C:\Windows\explorer.exe
        Image: C:\Windows\System32\cmd.exe
        CommandLine|contains|all:
            - 'powershell'
            - '.lnk'
    condition: selection
falsepositives:
    - Legitimate commands in .lnk files
level: medium
```
