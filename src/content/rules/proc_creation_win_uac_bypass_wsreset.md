---
title: Bypass UAC via WSReset.exe
summary: Detects use of WSReset.exe to bypass User Account Control (UAC). Adversaries use this technique to execute privileged processes.
sigma_id: d797268e-28a9-49a7-b9a8-2f5039011c5c
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1548.002
author: E.M. Anhaus (originally from Atomic Blue Detections, Tony Lambert), oscd.community, Florian Roth
date: '2019-10-24'
modified: '2022-05-13'
falsepositives:
  - Unknown sub processes of Wsreset.exe
references:
  - https://eqllib.readthedocs.io/en/latest/analytics/532b5ed4-7930-11e9-8f5c-d46d6d62a49e.html
  - https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
  - https://web.archive.org/web/20240812143656/https://www.activecyber.us/activelabs/windows-uac-bypass
  - https://web.archive.org/web/20200530031302/https://twitter.com/ReaQta/status/1222548288731217921
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Bypass UAC via WSReset.exe
id: d797268e-28a9-49a7-b9a8-2f5039011c5c
related:
    - id: bdc8918e-a1d5-49d1-9db7-ea0fd91aa2ae
      type: obsolete
status: test
description: Detects use of WSReset.exe to bypass User Account Control (UAC). Adversaries use this technique to execute privileged processes.
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/532b5ed4-7930-11e9-8f5c-d46d6d62a49e.html
    - https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
    - https://web.archive.org/web/20240812143656/https://www.activecyber.us/activelabs/windows-uac-bypass
    - https://web.archive.org/web/20200530031302/https://twitter.com/ReaQta/status/1222548288731217921
author: E.M. Anhaus (originally from Atomic Blue Detections, Tony Lambert), oscd.community, Florian Roth
date: 2019-10-24
modified: 2022-05-13
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\wsreset.exe'
    filter:
        - Image|endswith: '\conhost.exe'
        - OriginalFileName: 'CONHOST.EXE'
    condition: selection and not filter
falsepositives:
    - Unknown sub processes of Wsreset.exe
level: high
```
