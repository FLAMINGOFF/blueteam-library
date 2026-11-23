---
title: Potential PowerShell Execution Via DLL
summary: |-
  Detects potential PowerShell execution from a DLL instead of the usual PowerShell process as seen used in PowerShdll.
  This detection assumes that PowerShell commands are passed via the CommandLine.
sigma_id: 6812a10b-60ea-420c-832f-dfcc33b646ba
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218.011
author: Markus Neis, Nasreddine Bencherchali (Nextron Systems)
date: '2018-08-25'
modified: '2024-03-07'
falsepositives:
  - Unknown
references:
  - https://github.com/p3nt4/PowerShdll/blob/62cfa172fb4e1f7f4ac00ca942685baeb88ff356/README.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_powershell_execution_via_dll.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential PowerShell Execution Via DLL
id: 6812a10b-60ea-420c-832f-dfcc33b646ba
status: test
description: |
    Detects potential PowerShell execution from a DLL instead of the usual PowerShell process as seen used in PowerShdll.
    This detection assumes that PowerShell commands are passed via the CommandLine.
references:
    - https://github.com/p3nt4/PowerShdll/blob/62cfa172fb4e1f7f4ac00ca942685baeb88ff356/README.md
author: Markus Neis, Nasreddine Bencherchali (Nextron Systems)
date: 2018-08-25
modified: 2024-03-07
tags:
    - attack.stealth
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\InstallUtil.exe'
              - '\RegAsm.exe'
              - '\RegSvcs.exe'
              - '\regsvr32.exe'
              - '\rundll32.exe'
        - OriginalFileName:
              - 'InstallUtil.exe'
              - 'RegAsm.exe'
              - 'RegSvcs.exe'
              - 'REGSVR32.EXE'
              - 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains:
            - 'Default.GetString'
            - 'DownloadString'
            - 'FromBase64String'
            - 'ICM '
            - 'IEX '
            - 'Invoke-Command'
            - 'Invoke-Expression'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
