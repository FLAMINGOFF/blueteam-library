---
title: Driver/DLL Installation Via Odbcconf.EXE
summary: Detects execution of "odbcconf" with "INSTALLDRIVER" which installs a new ODBC driver. Attackers abuse this to install and run malicious DLLs.
sigma_id: 3f5491e2-8db8-496b-9e95-1029fce852d4
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218.008
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-05-22'
falsepositives:
  - Legitimate driver DLLs being registered via "odbcconf" will generate false positives. Investigate the path of the DLL and its contents to determine if the action is authorized.
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
  - https://web.archive.org/web/20191023232753/https://twitter.com/Hexacorn/status/1187143326673330176
  - https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_odbcconf_driver_install.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Driver/DLL Installation Via Odbcconf.EXE
id: 3f5491e2-8db8-496b-9e95-1029fce852d4
related:
    - id: cb0fe7c5-f3a3-484d-aa25-d350a7912729
      type: similar
status: test
description: Detects execution of "odbcconf" with "INSTALLDRIVER" which installs a new ODBC driver. Attackers abuse this to install and run malicious DLLs.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
    - https://web.archive.org/web/20191023232753/https://twitter.com/Hexacorn/status/1187143326673330176
    - https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-22
tags:
    - attack.stealth
    - attack.t1218.008
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\odbcconf.exe'
        - OriginalFileName: 'odbcconf.exe'
    selection_cli:
        # Note: The "/A" flag is not required to call a specific action
        CommandLine|contains|all:
            - 'INSTALLDRIVER '
            - '.dll'
    condition: all of selection_*
falsepositives:
    - Legitimate driver DLLs being registered via "odbcconf" will generate false positives. Investigate the path of the DLL and its contents to determine if the action is authorized.
level: medium
```
