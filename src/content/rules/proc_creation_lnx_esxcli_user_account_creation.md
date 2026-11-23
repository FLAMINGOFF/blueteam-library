---
title: ESXi Account Creation Via ESXCLI
summary: Detects user account creation on ESXi system via esxcli
sigma_id: b28e4eb3-8bbc-4f0c-819f-edfe8e2f25db
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0003
  - TA0002
techniques:
  - T1136
  - T1059.012
author: Cedric Maurugeon
date: '2023-08-22'
falsepositives:
  - Legitimate administration activities
references:
  - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_esxcli_user_account_creation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: ESXi Account Creation Via ESXCLI
id: b28e4eb3-8bbc-4f0c-819f-edfe8e2f25db
status: test
description: Detects user account creation on ESXi system via esxcli
references:
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
author: Cedric Maurugeon
date: 2023-08-22
tags:
    - attack.persistence
    - attack.execution
    - attack.t1136
    - attack.t1059.012
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains|all:
            - 'system '
            - 'account '
            - 'add '
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
