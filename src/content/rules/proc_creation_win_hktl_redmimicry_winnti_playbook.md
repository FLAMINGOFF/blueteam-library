---
title: HackTool - RedMimicry Winnti Playbook Execution
summary: Detects actions caused by the RedMimicry Winnti playbook a automated breach emulations utility
sigma_id: 95022b85-ff2a-49fa-939a-d7b8f56eeb9b
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1106
  - T1059.003
  - T1218.011
author: Alexander Rausch
date: '2020-06-24'
modified: '2023-03-01'
falsepositives:
  - Unknown
references:
  - https://web.archive.org/web/20240222070028/https://redmimicry.com/posts/redmimicry-winnti/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_redmimicry_winnti_playbook.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - RedMimicry Winnti Playbook Execution
id: 95022b85-ff2a-49fa-939a-d7b8f56eeb9b
status: test
description: Detects actions caused by the RedMimicry Winnti playbook a automated breach emulations utility
references:
    - https://web.archive.org/web/20240222070028/https://redmimicry.com/posts/redmimicry-winnti/
author: Alexander Rausch
date: 2020-06-24
modified: 2023-03-01
tags:
    - attack.execution
    - attack.stealth
    - attack.t1106
    - attack.t1059.003
    - attack.t1218.011
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\rundll32.exe'
            - '\cmd.exe'
        CommandLine|contains:
            - 'gthread-3.6.dll'
            - '\Windows\Temp\tmp.bat'
            - 'sigcmm-2.4.dll'
    condition: selection
falsepositives:
    - Unknown
level: high
```
