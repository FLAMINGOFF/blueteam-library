---
title: Ie4uinit Lolbin Use From Invalid Path
summary: Detect use of ie4uinit.exe to execute commands from a specially prepared ie4uinit.inf file from a directory other than the usual directories
sigma_id: d3bf399f-b0cf-4250-8bb4-dfc192ab81dc
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
author: frack113
date: '2022-05-07'
modified: '2022-05-16'
falsepositives:
  - ViberPC updater calls this binary with the following commandline "ie4uinit.exe -ClearIconCache"
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Ie4uinit/
  - https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_ie4uinit.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Ie4uinit Lolbin Use From Invalid Path
id: d3bf399f-b0cf-4250-8bb4-dfc192ab81dc
status: test
description: Detect use of ie4uinit.exe to execute commands from a specially prepared ie4uinit.inf file from a directory other than the usual directories
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Ie4uinit/
    - https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/
author: frack113
date: 2022-05-07
modified: 2022-05-16
tags:
    - attack.stealth
    - attack.t1218
logsource:
    product: windows
    category: process_creation
detection:
    lolbin:
        - Image|endswith: '\ie4uinit.exe'
        - OriginalFileName: 'IE4UINIT.EXE'
    filter_correct:
        CurrentDirectory:
            - 'c:\windows\system32\'
            - 'c:\windows\sysWOW64\'
    filter_missing:
        CurrentDirectory: null
    condition: lolbin and not 1 of filter_*
falsepositives:
    - ViberPC updater calls this binary with the following commandline "ie4uinit.exe -ClearIconCache"
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_lolbin_ie4uinit/info.yml
```
