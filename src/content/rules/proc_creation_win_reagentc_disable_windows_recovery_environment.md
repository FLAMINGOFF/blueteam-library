---
title: Windows Recovery Environment Disabled Via Reagentc
summary: |-
  Detects attempts to disable windows recovery environment using Reagentc.
  ReAgentc.exe is a command-line tool in Windows used to manage the Windows Recovery Environment (WinRE).
  It allows users to enable, disable, and configure WinRE, which is used for troubleshooting and repairing common boot issues.
sigma_id: db1c21e4-cd66-4b4e-85ca-590f0780529c
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1490
author: Daniel Koifman (KoifSec), Michael Vilshin
date: '2025-07-31'
falsepositives:
  - Legitimate administrative activity
references:
  - https://www.elastic.co/security-labs/maas-appeal-an-infostealer-rises-from-the-ashes
  - https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reagentc_disable_windows_recovery_environment.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Windows Recovery Environment Disabled Via Reagentc
id: db1c21e4-cd66-4b4e-85ca-590f0780529c
status: experimental
description: |
    Detects attempts to disable windows recovery environment using Reagentc.
    ReAgentc.exe is a command-line tool in Windows used to manage the Windows Recovery Environment (WinRE).
    It allows users to enable, disable, and configure WinRE, which is used for troubleshooting and repairing common boot issues.
references:
    - https://www.elastic.co/security-labs/maas-appeal-an-infostealer-rises-from-the-ashes
    - https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11
author: Daniel Koifman (KoifSec), Michael Vilshin
date: 2025-07-31
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:   # Example command simulated:  reagentc /disable
        - Image|endswith: '\reagentc.exe'
        - OriginalFileName: 'reagentc.exe'
    selection_cli:
        CommandLine|contains|windash: '/disable'
    condition: all of selection_*
falsepositives:
    - Legitimate administrative activity
level: medium
```
