---
title: HackTool - SysmonEnte Execution
summary: Detects the use of SysmonEnte, a tool to attack the integrity of Sysmon
sigma_id: d29ada0f-af45-4f27-8f32-f7b77c3dbc4e
status: test
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0112
techniques:
  - T1685.001
author: Florian Roth (Nextron Systems)
date: '2022-09-07'
modified: '2026-06-29'
falsepositives:
  - Unknown
references:
  - https://codewhitesec.blogspot.com/2022/09/attacks-on-sysmon-revisited-sysmonente.html
  - https://github.com/codewhitesec/SysmonEnte/
  - https://github.com/codewhitesec/SysmonEnte/blob/fe267690fcc799fbda15398243615a30451d9099/screens/1.png
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_hktl_sysmonente.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SysmonEnte Execution
id: d29ada0f-af45-4f27-8f32-f7b77c3dbc4e
status: test
description: Detects the use of SysmonEnte, a tool to attack the integrity of Sysmon
references:
    - https://codewhitesec.blogspot.com/2022/09/attacks-on-sysmon-revisited-sysmonente.html
    - https://github.com/codewhitesec/SysmonEnte/
    - https://github.com/codewhitesec/SysmonEnte/blob/fe267690fcc799fbda15398243615a30451d9099/screens/1.png
author: Florian Roth (Nextron Systems)
date: 2022-09-07
modified: 2026-06-29
tags:
    - attack.defense-impairment
    - attack.t1685.001
logsource:
    category: process_access
    product: windows
detection:
    selection_sysmon:
        TargetImage|contains:
            - ':\Windows\Sysmon.exe'
            - ':\Windows\Sysmon64.exe'
            - ':\Windows\Sysmon64a.exe'
        GrantedAccess: '0x1400'
    selection_calltrace:
        CallTrace: 'Ente'
    filter_main_generic:
        SourceImage|contains:
            - ':\Program Files (x86)\'
            - ':\Program Files\'
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
    filter_main_msdefender:
        SourceImage|contains: ':\ProgramData\Microsoft\Windows Defender\Platform\'
        SourceImage|endswith: '\MsMpEng.exe'
    condition: ( selection_sysmon and not 1 of filter_main_* ) or selection_calltrace
falsepositives:
    - Unknown
level: high
```
