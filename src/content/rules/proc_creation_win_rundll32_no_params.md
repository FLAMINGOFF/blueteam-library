---
title: Rundll32 Execution Without CommandLine Parameters
summary: Detects suspicious start of rundll32.exe without any parameters as found in CobaltStrike beacon activity
sigma_id: 1775e15e-b61b-4d14-a1a3-80981298085a
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1202
author: Florian Roth (Nextron Systems)
date: '2021-05-27'
modified: '2023-08-31'
falsepositives:
  - Possible but rare
references:
  - https://www.cobaltstrike.com/help-opsec
  - https://twitter.com/ber_m1ng/status/1397948048135778309
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_no_params.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Rundll32 Execution Without CommandLine Parameters
id: 1775e15e-b61b-4d14-a1a3-80981298085a
status: test
description: Detects suspicious start of rundll32.exe without any parameters as found in CobaltStrike beacon activity
references:
    - https://www.cobaltstrike.com/help-opsec
    - https://twitter.com/ber_m1ng/status/1397948048135778309
author: Florian Roth (Nextron Systems)
date: 2021-05-27
modified: 2023-08-31
tags:
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|endswith:
            - '\rundll32.exe'
            - '\rundll32.exe"'
            - '\rundll32'
    filter:
        ParentImage|contains:
            - '\AppData\Local\'
            - '\Microsoft\Edge\'
    condition: selection and not filter
falsepositives:
    - Possible but rare
level: high
```
