---
title: Tamper Windows Defender Remove-MpPreference
summary: Detects attempts to remove Windows Defender configurations using the 'MpPreference' cmdlet
sigma_id: 07e3cb2c-0608-410d-be4b-1511cb1a0448
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-05'
falsepositives:
  - Legitimate PowerShell scripts
references:
  - https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-controlled-folder-access-event-search/ba-p/2326088
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_remove_mppreference.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Tamper Windows Defender Remove-MpPreference
id: 07e3cb2c-0608-410d-be4b-1511cb1a0448
related:
    - id: ae2bdd58-0681-48ac-be7f-58ab4e593458
      type: similar
status: test
description: Detects attempts to remove Windows Defender configurations using the 'MpPreference' cmdlet
references:
    - https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-controlled-folder-access-event-search/ba-p/2326088
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-05
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: windows
    category: process_creation
detection:
    selection_remove:
        CommandLine|contains: 'Remove-MpPreference'
    selection_tamper:
        CommandLine|contains:
            - '-ControlledFolderAccessProtectedFolders '
            - '-AttackSurfaceReductionRules_Ids '
            - '-AttackSurfaceReductionRules_Actions '
            - '-CheckForSignaturesBeforeRunningScan '
    condition: all of selection_*
falsepositives:
    - Legitimate PowerShell scripts
level: high
```
