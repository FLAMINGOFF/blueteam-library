---
title: HackTool - SharpLDAPmonitor Execution
summary: Detects execution of the SharpLDAPmonitor. Which can monitor the creation, deletion and changes to LDAP objects.
sigma_id: 9f8fc146-1d1a-4dbf-b8fd-dfae15e08541
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-12-30'
modified: '2023-02-14'
falsepositives:
  - Unknown
references:
  - https://github.com/p0dalirius/LDAPmonitor
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_sharp_ldap_monitor.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SharpLDAPmonitor Execution
id: 9f8fc146-1d1a-4dbf-b8fd-dfae15e08541
status: test
description: Detects execution of the SharpLDAPmonitor. Which can monitor the creation, deletion and changes to LDAP objects.
references:
    - https://github.com/p0dalirius/LDAPmonitor
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-30
modified: 2023-02-14
tags:
    - attack.discovery
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\SharpLDAPmonitor.exe'
        - OriginalFileName: 'SharpLDAPmonitor.exe'
    selection_cli:
        CommandLine|contains|all:
            - '/user:'
            - '/pass:'
            - '/dcip:'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium
```
