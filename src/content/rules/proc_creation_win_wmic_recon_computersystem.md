---
title: Computer System Reconnaissance Via Wmic.EXE
summary: Detects execution of wmic utility with the "computersystem" flag in order to obtain information about the machine such as the domain, username, model, etc.
sigma_id: 9d7ca793-f6bd-471c-8d0f-11e68b2f0d2f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
  - TA0002
techniques:
  - T1047
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-08'
modified: '2023-02-14'
falsepositives:
  - Unknown
references:
  - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wmic_recon_computersystem.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Computer System Reconnaissance Via Wmic.EXE
id: 9d7ca793-f6bd-471c-8d0f-11e68b2f0d2f
status: test
description: Detects execution of wmic utility with the "computersystem" flag in order to obtain information about the machine such as the domain, username, model, etc.
references:
    - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-08
modified: 2023-02-14
tags:
    - attack.discovery
    - attack.execution
    - attack.t1047
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\wmic.exe'
        - OriginalFileName: 'wmic.exe'
    selection_cli:
        CommandLine|contains: 'computersystem'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_wmic_recon_computersystem/info.yml
```
