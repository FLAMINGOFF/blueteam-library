---
title: Renamed BOINC Client Execution
summary: Detects the execution of a renamed BOINC binary.
sigma_id: 30d07da2-83ab-45d8-ae75-ec7c0edcaffc
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1553
author: Matt Anderson (Huntress)
date: '2024-07-23'
falsepositives:
  - Unknown
references:
  - https://boinc.berkeley.edu/
  - https://www.virustotal.com/gui/file/91e405e8a527023fb8696624e70498ae83660fe6757cef4871ce9bcc659264d3/details
  - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_boinc.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed BOINC Client Execution
id: 30d07da2-83ab-45d8-ae75-ec7c0edcaffc
status: test
description: Detects the execution of a renamed BOINC binary.
references:
    - https://boinc.berkeley.edu/
    - https://www.virustotal.com/gui/file/91e405e8a527023fb8696624e70498ae83660fe6757cef4871ce9bcc659264d3/details
    - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
author: Matt Anderson (Huntress)
date: 2024-07-23
tags:
    - attack.defense-impairment
    - attack.t1553
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'BOINC.exe'
    filter_main_legit_name:
        Image|endswith: '\BOINC.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
