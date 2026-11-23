---
title: UAC Bypass via Windows Firewall Snap-In Hijack
summary: Detects attempts to bypass User Account Control (UAC) by hijacking the Microsoft Management Console (MMC) Windows Firewall snap-in
sigma_id: e52cb31c-10ed-4aea-bcb7-593c9f4a315b
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1548
author: Tim Rauch, Elastic (idea)
date: '2022-09-27'
falsepositives:
  - Unknown
references:
  - https://www.elastic.co/guide/en/security/current/uac-bypass-via-windows-firewall-snap-in-hijack.html#uac-bypass-via-windows-firewall-snap-in-hijack
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_uac_bypass_hijacking_firwall_snap_in.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: UAC Bypass via Windows Firewall Snap-In Hijack
id: e52cb31c-10ed-4aea-bcb7-593c9f4a315b
status: test
description: Detects attempts to bypass User Account Control (UAC) by hijacking the Microsoft Management Console (MMC) Windows Firewall snap-in
references:
    - https://www.elastic.co/guide/en/security/current/uac-bypass-via-windows-firewall-snap-in-hijack.html#uac-bypass-via-windows-firewall-snap-in-hijack
author: Tim Rauch, Elastic (idea)
date: 2022-09-27
tags:
    - attack.privilege-escalation
    - attack.t1548
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\mmc.exe'
        ParentCommandLine|contains: 'WF.msc'
    filter:
        Image|endswith: '\WerFault.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
```
