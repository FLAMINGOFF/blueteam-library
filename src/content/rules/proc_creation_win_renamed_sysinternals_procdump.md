---
title: Renamed ProcDump Execution
summary: |-
  Detects the execution of a renamed ProcDump executable.
  This often done by attackers or malware in order to evade defensive mechanisms.
sigma_id: 4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1036.003
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: '2019-11-18'
modified: '2026-06-29'
falsepositives:
  - Procdump illegally bundled with legitimate software.
  - Administrators who rename binaries (should be investigated).
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed ProcDump Execution
id: 4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67
related:
    - id: 03795938-1387-481b-9f4c-3f6241e604fe
      type: obsolete
status: test
description: |
    Detects the execution of a renamed ProcDump executable.
    This often done by attackers or malware in order to evade defensive mechanisms.
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2019-11-18
modified: 2026-06-29
tags:
    - attack.stealth
    - attack.t1036.003
logsource:
    product: windows
    category: process_creation
detection:
    selection_ofn:
        OriginalFileName: 'procdump'
    selection_cli_dump_flag:
        CommandLine|contains|windash:
            - ' -ma ' # Full Dump
            - ' -mp ' # Mini Plus
    selection_cli_eula_flag:
        # Note: Even though the "accepteula" flag isn't required. We add it to avoid collision with similar utilities.
        CommandLine|contains|windash: ' /accepteula'
    filter_main_known_names:
        Image|endswith:
            - '\procdump.exe'
            - '\procdump64.exe'
            - '\procdump64a.exe'
    condition: (selection_ofn or all of selection_cli_*) and not 1 of filter_main_*
falsepositives:
    - Procdump illegally bundled with legitimate software.
    - Administrators who rename binaries (should be investigated).
level: high
```
