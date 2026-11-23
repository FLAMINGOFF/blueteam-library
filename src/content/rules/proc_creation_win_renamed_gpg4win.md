---
title: Renamed Gpg.EXE Execution
summary: Detects the execution of a renamed "gpg.exe". Often used by ransomware and loaders to decrypt/encrypt data.
sigma_id: ec0722a3-eb5c-4a56-8ab2-bf6f20708592
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1486
author: Nasreddine Bencherchali (Nextron Systems), frack113
date: '2023-08-09'
falsepositives: []
references:
  - https://securelist.com/locked-out/68960/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_gpg4win.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed Gpg.EXE Execution
id: ec0722a3-eb5c-4a56-8ab2-bf6f20708592
status: test
description: Detects the execution of a renamed "gpg.exe". Often used by ransomware and loaders to decrypt/encrypt data.
references:
    - https://securelist.com/locked-out/68960/
author: Nasreddine Bencherchali (Nextron Systems), frack113
date: 2023-08-09
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'gpg.exe'
    filter_main_img:
        Image|endswith:
            - '\gpg.exe'
            - '\gpg2.exe'
    condition: selection and not 1 of filter_main_*
level: high
```
