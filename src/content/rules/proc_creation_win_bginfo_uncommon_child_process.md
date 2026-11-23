---
title: Uncommon Child Process Of BgInfo.EXE
summary: Detects uncommon child processes of "BgInfo.exe" which could be a sign of potential abuse of the binary to proxy execution via external VBScript
sigma_id: aaf46cdc-934e-4284-b329-34aa701e3771
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.005
  - T1218
  - T1202
author: Nasreddine Bencherchali (Nextron Systems), Beyu Denis, oscd.community
date: '2019-10-26'
modified: '2023-08-16'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Bginfo/
  - https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_bginfo_uncommon_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon Child Process Of BgInfo.EXE
id: aaf46cdc-934e-4284-b329-34aa701e3771
related:
    - id: 811f459f-9231-45d4-959a-0266c6311987
      type: similar
status: test
description: Detects uncommon child processes of "BgInfo.exe" which could be a sign of potential abuse of the binary to proxy execution via external VBScript
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Bginfo/
    - https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/
author: Nasreddine Bencherchali (Nextron Systems), Beyu Denis, oscd.community
date: 2019-10-26
modified: 2023-08-16
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
    selection:
        ParentImage|endswith:
            - '\bginfo.exe'
            - '\bginfo64.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
