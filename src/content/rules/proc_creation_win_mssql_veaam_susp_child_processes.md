---
title: Suspicious Child Process Of Veeam Dabatase
summary: Detects suspicious child processes of the Veeam service process. This could indicate potential RCE or SQL Injection.
sigma_id: d55b793d-f847-4eea-b59a-5ab09908ac90
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0001
  - TA0003
  - TA0004
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-05-04'
falsepositives: []
references:
  - https://labs.withsecure.com/publications/fin7-target-veeam-servers
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mssql_veaam_susp_child_processes.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Child Process Of Veeam Dabatase
id: d55b793d-f847-4eea-b59a-5ab09908ac90
related:
    - id: 869b9ca7-9ea2-4a5a-8325-e80e62f75445
      type: similar
status: test
description: Detects suspicious child processes of the Veeam service process. This could indicate potential RCE or SQL Injection.
references:
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-04
tags:
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\sqlservr.exe'
        ParentCommandLine|contains: 'VEEAMSQL'
    selection_child_1:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wsl.exe'
            - '\wt.exe'
        CommandLine|contains:
            - '-ex '
            - 'bypass'
            - 'cscript'
            - 'DownloadString'
            - 'http://'
            - 'https://'
            - 'mshta'
            - 'regsvr32'
            - 'rundll32'
            - 'wscript'
            - 'copy '
    selection_child_2:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
            - '\netstat.exe'
            - '\nltest.exe'
            - '\ping.exe'
            - '\tasklist.exe'
            - '\whoami.exe'
    condition: selection_parent and 1 of selection_child_*
level: critical
```
