---
title: Potentially Suspicious DLL Registered Via Odbcconf.EXE
summary: Detects execution of "odbcconf" with the "REGSVR" action where the DLL in question doesn't contain a ".dll" extension. Which is often used as a method to evade defenses.
sigma_id: ba4cfc11-d0fa-4d94-bf20-7c332c412e76
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218.008
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-05-22'
falsepositives:
  - Unlikely
references:
  - https://learn.microsoft.com/en-us/sql/odbc/odbcconf-exe?view=sql-server-ver16
  - https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
  - https://www.trendmicro.com/en_us/research/17/h/backdoor-carrying-emails-set-sights-on-russian-speaking-businesses.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_odbcconf_register_dll_regsvr_susp.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potentially Suspicious DLL Registered Via Odbcconf.EXE
id: ba4cfc11-d0fa-4d94-bf20-7c332c412e76
related:
    - id: 9f0a8bf3-a65b-440a-8c1e-5cb1547c8e70
      type: derived
status: test
description: Detects execution of "odbcconf" with the "REGSVR" action where the DLL in question doesn't contain a ".dll" extension. Which is often used as a method to evade defenses.
references:
    - https://learn.microsoft.com/en-us/sql/odbc/odbcconf-exe?view=sql-server-ver16
    - https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
    - https://www.trendmicro.com/en_us/research/17/h/backdoor-carrying-emails-set-sights-on-russian-speaking-businesses.html
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
        CommandLine|contains: 'REGSVR '
    filter_main_dll_ext:
        CommandLine|contains: '.dll'
    condition: all of selection_* and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
