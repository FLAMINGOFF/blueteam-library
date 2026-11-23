---
title: ESXi Admin Permission Assigned To Account Via ESXCLI
summary: Detects execution of the "esxcli" command with the "system" and "permission" flags in order to assign admin permissions to an account.
sigma_id: 9691f58d-92c1-4416-8bf3-2edd753ec9cf
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0003
  - TA0002
  - TA0004
techniques:
  - T1059.012
  - T1098
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-09-04'
falsepositives:
  - Legitimate administration activities
references:
  - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_esxcli_permission_change_admin.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: ESXi Admin Permission Assigned To Account Via ESXCLI
id: 9691f58d-92c1-4416-8bf3-2edd753ec9cf
status: test
description: Detects execution of the "esxcli" command with the "system" and "permission" flags in order to assign admin permissions to an account.
references:
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-09-04
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1059.012
    - attack.t1098
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains: 'system'
        CommandLine|contains|all:
            - ' permission '
            - ' set'
            - 'Admin'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: high
```
