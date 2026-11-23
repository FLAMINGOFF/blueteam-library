---
title: Security Privileges Enumeration Via Whoami.EXE
summary: Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privileges. This is often used after a privilege escalation attempt.
sigma_id: 97a80ec7-0e2f-4d05-9ef4-65760e634f6b
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0007
techniques:
  - T1033
author: Florian Roth (Nextron Systems)
date: '2021-05-05'
modified: '2023-02-28'
falsepositives:
  - Unknown
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_whoami_priv_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Security Privileges Enumeration Via Whoami.EXE
id: 97a80ec7-0e2f-4d05-9ef4-65760e634f6b
status: test
description: Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privileges. This is often used after a privilege escalation attempt.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
author: Florian Roth (Nextron Systems)
date: 2021-05-05
modified: 2023-02-28
tags:
    - attack.privilege-escalation
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\whoami.exe'
        - OriginalFileName: 'whoami.exe'
    selection_cli:
        CommandLine|contains:
            - ' /priv'
            - ' -priv'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_whoami_priv_discovery/info.yml
```
