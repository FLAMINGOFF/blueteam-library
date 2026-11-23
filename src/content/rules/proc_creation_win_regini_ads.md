---
title: Suspicious Registry Modification From ADS Via Regini.EXE
summary: Detects the import of an alternate data stream with regini.exe, regini.exe can be used to modify registry keys.
sigma_id: 77946e79-97f1-45a2-84b4-f37b5c0d8682
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0112
techniques:
  - T1112
author: Eli Salem, Sander Wiebing, oscd.community
date: '2020-10-12'
modified: '2023-02-08'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Regini/
  - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regini
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_regini_ads.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Registry Modification From ADS Via Regini.EXE
id: 77946e79-97f1-45a2-84b4-f37b5c0d8682
related:
    - id: 5f60740a-f57b-4e76-82a1-15b6ff2cb134
      type: derived
status: test
description: Detects the import of an alternate data stream with regini.exe, regini.exe can be used to modify registry keys.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Regini/
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regini
author: Eli Salem, Sander Wiebing, oscd.community
date: 2020-10-12
modified: 2023-02-08
tags:
    - attack.persistence
    - attack.defense-impairment
    - attack.t1112
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\regini.exe'
        - OriginalFileName: 'REGINI.EXE'
    selection_re:
        CommandLine|re: ':[^ \\]'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
