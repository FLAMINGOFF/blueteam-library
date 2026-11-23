---
title: Potential Persistence Via Logon Scripts - CommandLine
summary: Detects the addition of a new LogonScript to the registry value "UserInitMprLogonScript" for potential persistence
sigma_id: 21d856f9-9281-4ded-9377-51a1a6e2a432
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
techniques:
  - T1037.001
author: Tom Ueltschi (@c_APT_ure)
date: '2019-01-12'
modified: '2023-06-09'
falsepositives:
  - Legitimate addition of Logon Scripts via the command line by administrators or third party tools
references:
  - https://cocomelonc.github.io/persistence/2022/12/09/malware-pers-20.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_registry_logon_script.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Persistence Via Logon Scripts - CommandLine
id: 21d856f9-9281-4ded-9377-51a1a6e2a432
related:
    - id: 0a98a10c-685d-4ab0-bddc-b6bdd1d48458
      type: derived
status: test
description: Detects the addition of a new LogonScript to the registry value "UserInitMprLogonScript" for potential persistence
references:
    - https://cocomelonc.github.io/persistence/2022/12/09/malware-pers-20.html
author: Tom Ueltschi (@c_APT_ure)
date: 2019-01-12
modified: 2023-06-09
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1037.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'UserInitMprLogonScript'
    condition: selection
falsepositives:
    - Legitimate addition of Logon Scripts via the command line by administrators or third party tools
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_registry_logon_script/info.yml
```
