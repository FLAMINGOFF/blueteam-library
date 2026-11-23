---
title: Suspicious Child Process Of BgInfo.EXE
summary: Detects suspicious child processes of "BgInfo.exe" which could be a sign of potential abuse of the binary to proxy execution via external VBScript
sigma_id: 811f459f-9231-45d4-959a-0266c6311987
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1059.005
  - T1218
  - T1202
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-08-16'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Bginfo/
  - https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_bginfo_suspicious_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Child Process Of BgInfo.EXE
id: 811f459f-9231-45d4-959a-0266c6311987
related:
    - id: aaf46cdc-934e-4284-b329-34aa701e3771
      type: similar
status: test
description: Detects suspicious child processes of "BgInfo.exe" which could be a sign of potential abuse of the binary to proxy execution via external VBScript
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Bginfo/
    - https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-16
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.005
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\bginfo.exe'
            - '\bginfo64.exe'
    selection_child:
        - Image|endswith:
              - '\calc.exe'
              - '\cmd.exe'
              - '\cscript.exe'
              - '\mshta.exe'
              - '\notepad.exe'
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\wscript.exe'
        - Image|contains:
              - '\AppData\Local\'
              - '\AppData\Roaming\'
              - ':\Users\Public\'
              - ':\Temp\'
              - ':\Windows\Temp\'
              - ':\PerfLogs\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
