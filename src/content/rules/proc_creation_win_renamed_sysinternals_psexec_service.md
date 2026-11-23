---
title: Renamed PsExec Service Execution
summary: Detects suspicious launch of a renamed version of the PSEXESVC service with, which is not often used by legitimate administrators
sigma_id: 51ae86a2-e2e1-4097-ad85-c46cb6851de4
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Florian Roth (Nextron Systems)
date: '2022-07-21'
falsepositives:
  - Legitimate administrative tasks
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
  - https://www.youtube.com/watch?v=ro2QuZTIMBM
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_psexec_service.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed PsExec Service Execution
id: 51ae86a2-e2e1-4097-ad85-c46cb6851de4
status: test
description: Detects suspicious launch of a renamed version of the PSEXESVC service with, which is not often used by legitimate administrators
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
    - https://www.youtube.com/watch?v=ro2QuZTIMBM
author: Florian Roth (Nextron Systems)
date: 2022-07-21
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'psexesvc.exe'
    filter:
        Image: 'C:\Windows\PSEXESVC.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative tasks
level: high
```
