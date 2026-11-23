---
title: User Added To Highly Privileged Group
summary: Detects addition of users to highly privileged groups via "Net" or "Add-LocalGroupMember".
sigma_id: 10fb649c-3600-4d37-b1e6-56ea90bb7e09
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
techniques:
  - T1098
author: Nasreddine Bencherchali (Nextron Systems)
date: '2024-02-23'
falsepositives:
  - Administrative activity that must be investigated
references:
  - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_add_user_privileged_group.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: User Added To Highly Privileged Group
id: 10fb649c-3600-4d37-b1e6-56ea90bb7e09 # Privileged groups
related:
    - id: ffa28e60-bdb1-46e0-9f82-05f7a61cc06e # Remote Desktop groups
      type: similar
    - id: ad720b90-25ad-43ff-9b5e-5c841facc8e5 # Admin groups
      type: similar
status: test
description: Detects addition of users to highly privileged groups via "Net" or "Add-LocalGroupMember".
references:
    - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-02-23
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1098
logsource:
    category: process_creation
    product: windows
detection:
    selection_main:
        - CommandLine|contains|all:
              # net.exe
              - 'localgroup '
              - ' /add'
        - CommandLine|contains|all:
              # powershell.exe
              - 'Add-LocalGroupMember '
              - ' -Group '
    selection_group:
        CommandLine|contains:
            - 'Group Policy Creator Owners'
            - 'Schema Admins'
    condition: all of selection_*
falsepositives:
    - Administrative activity that must be investigated
level: high
```
