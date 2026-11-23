---
title: MSDT Execution Via Answer File
summary: Detects execution of "msdt.exe" using an answer file which is simulating the legitimate way of calling msdt via "pcwrun.exe" (For example from the compatibility tab).
sigma_id: 9c8c7000-3065-44a8-a555-79bcba5d9955
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-13'
modified: '2025-10-29'
falsepositives:
  - Possible undocumented parents of "msdt" other than "pcwrun".
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Msdt/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_msdt_answer_file_exec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: MSDT Execution Via Answer File
id: 9c8c7000-3065-44a8-a555-79bcba5d9955
status: test
description: |
    Detects execution of "msdt.exe" using an answer file which is simulating the legitimate way of calling msdt via "pcwrun.exe" (For example from the compatibility tab).
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Msdt/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-13
modified: 2025-10-29
tags:
    - attack.stealth
    - attack.t1218
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\msdt.exe'
        CommandLine|contains: '\WINDOWS\diagnostics\index\PCWDiagnostic.xml'
        CommandLine|contains|windash: ' -af '
    filter_main_pcwrun:
        ParentImage|endswith: '\pcwrun.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Possible undocumented parents of "msdt" other than "pcwrun".
level: high
```
