---
title: Potential Credential Dumping Via LSASS Process Clone
summary: Detects a suspicious LSASS process process clone that could be a sign of credential dumping activity
sigma_id: c8da0dfd-4ed0-4b68-962d-13c9c884384e
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003
  - T1003.001
author: Florian Roth (Nextron Systems), Samir Bousseaden
date: '2021-11-27'
modified: '2023-03-02'
falsepositives:
  - Unknown
references:
  - https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/
  - https://web.archive.org/web/20211128075033/https://twitter.com/Hexacorn/status/1420053502554951689
  - https://twitter.com/SBousseaden/status/1464566846594691073?s=20
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lsass_process_clone.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Credential Dumping Via LSASS Process Clone
id: c8da0dfd-4ed0-4b68-962d-13c9c884384e
status: test
description: Detects a suspicious LSASS process process clone that could be a sign of credential dumping activity
references:
    - https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/
    - https://web.archive.org/web/20211128075033/https://twitter.com/Hexacorn/status/1420053502554951689
    - https://twitter.com/SBousseaden/status/1464566846594691073?s=20
author: Florian Roth (Nextron Systems), Samir Bousseaden
date: 2021-11-27
modified: 2023-03-02
tags:
    - attack.credential-access
    - attack.t1003
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\Windows\System32\lsass.exe'
        Image|endswith: '\Windows\System32\lsass.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
