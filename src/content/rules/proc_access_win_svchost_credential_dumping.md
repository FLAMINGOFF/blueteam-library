---
title: Credential Dumping Attempt Via Svchost
summary: Detects when a process tries to access the memory of svchost to potentially dump credentials.
sigma_id: 174afcfa-6e40-4ae9-af64-496546389294
status: test
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0004
techniques:
  - T1548
author: Florent Labouyrie
date: '2021-04-30'
modified: '2022-10-09'
falsepositives:
  - Unknown
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_svchost_credential_dumping.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Credential Dumping Attempt Via Svchost
id: 174afcfa-6e40-4ae9-af64-496546389294
status: test
description: Detects when a process tries to access the memory of svchost to potentially dump credentials.
references:
    - Internal Research
author: Florent Labouyrie
date: 2021-04-30
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.t1548
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\svchost.exe'
        GrantedAccess: '0x143a'
    filter_main_known_processes:
        SourceImage|endswith:
            - '\services.exe'
            - '\msiexec.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
