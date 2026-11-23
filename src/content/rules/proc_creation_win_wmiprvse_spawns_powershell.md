---
title: Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell
summary: Detects Powershell as a child of the WmiPrvSE process. Which could be a sign of lateral movement via WMI.
sigma_id: 692f0bec-83ba-4d04-af7e-e884a96059b6
status: stable
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1047
  - T1059.001
author: Markus Neis @Karneades
date: '2019-04-03'
modified: '2023-03-29'
falsepositives:
  - AppvClient
  - CCM
  - WinRM
references:
  - https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wmiprvse_spawns_powershell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell
id: 692f0bec-83ba-4d04-af7e-e884a96059b6
related:
    - id: 8a582fe2-0882-4b89-a82a-da6b2dc32937
      type: similar
    - id: d21374ff-f574-44a7-9998-4a8c8bf33d7d
      type: similar
status: stable
description: Detects Powershell as a child of the WmiPrvSE process. Which could be a sign of lateral movement via WMI.
references:
    - https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e
author: Markus Neis @Karneades
date: 2019-04-03
modified: 2023-03-29
tags:
    - attack.execution
    - attack.t1047
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\WmiPrvSE.exe'
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
    condition: all of selection_*
falsepositives:
    - AppvClient
    - CCM
    - WinRM
level: medium
```
