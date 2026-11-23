---
title: MpiExec Lolbin
summary: Detects a certain command line flag combination used by mpiexec.exe LOLBIN from HPC pack that can be used to execute any other binary
sigma_id: 729ce0ea-5d8f-4769-9762-e35de441586d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218
author: Florian Roth (Nextron Systems)
date: '2022-01-11'
modified: '2024-11-23'
falsepositives:
  - Unknown
references:
  - https://twitter.com/mrd0x/status/1465058133303246867
  - https://learn.microsoft.com/en-us/powershell/high-performance-computing/mpiexec?view=hpc19-ps
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_mpiexec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: MpiExec Lolbin
id: 729ce0ea-5d8f-4769-9762-e35de441586d
status: test
description: Detects a certain command line flag combination used by mpiexec.exe LOLBIN from HPC pack that can be used to execute any other binary
references:
    - https://twitter.com/mrd0x/status/1465058133303246867
    - https://learn.microsoft.com/en-us/powershell/high-performance-computing/mpiexec?view=hpc19-ps
author: Florian Roth (Nextron Systems)
date: 2022-01-11
modified: 2024-11-23
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        - Image|endswith: '\mpiexec.exe'
        - Hashes|contains: 'IMPHASH=d8b52ef6aaa3a81501bdfff9dbb96217'
    selection_flags:
        CommandLine|contains:
            - ' /n 1 '
            - ' -n 1 '
    condition: all of selection*
falsepositives:
    - Unknown
level: high
```
