---
title: Suspicious Process Masquerading As SvcHost.EXE
summary: |-
  Detects a suspicious process that is masquerading as the legitimate "svchost.exe" by naming its binary "svchost.exe" and executing from an uncommon location.
  Adversaries often disguise their malicious binaries by naming them after legitimate system processes like "svchost.exe" to evade detection.
sigma_id: be58d2e2-06c8-4f58-b666-b99f6dc3b6cd
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1036.005
author: Swachchhanda Shrawan Poudel
date: '2024-08-07'
falsepositives:
  - Unlikely
references:
  - https://tria.ge/240731-jh4crsycnb/behavioral2
  - https://redcanary.com/blog/threat-detection/process-masquerading/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Process Masquerading As SvcHost.EXE
id: be58d2e2-06c8-4f58-b666-b99f6dc3b6cd
related:
    - id: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
      type: similar
    - id: e4a6b256-3e47-40fc-89d2-7a477edd6915
      type: similar
status: test
description: |
    Detects a suspicious process that is masquerading as the legitimate "svchost.exe" by naming its binary "svchost.exe" and executing from an uncommon location.
    Adversaries often disguise their malicious binaries by naming them after legitimate system processes like "svchost.exe" to evade detection.
references:
    - https://tria.ge/240731-jh4crsycnb/behavioral2
    - https://redcanary.com/blog/threat-detection/process-masquerading/
author: Swachchhanda Shrawan Poudel
date: 2024-08-07
tags:
    - attack.stealth
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
    filter_main_img_location:
        Image:
            - 'C:\Windows\System32\svchost.exe'
            - 'C:\Windows\SysWOW64\svchost.exe'
    filter_main_ofn:
        OriginalFileName: 'svchost.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution/info.yml
```
