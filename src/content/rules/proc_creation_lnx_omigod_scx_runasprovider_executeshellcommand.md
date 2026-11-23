---
title: OMIGOD SCX RunAsProvider ExecuteShellCommand
summary: |-
  Rule to detect the use of the SCX RunAsProvider Invoke_ExecuteShellCommand to execute any UNIX/Linux command using the /bin/sh shell.
  SCXcore, started as the Microsoft Operations Manager UNIX/Linux Agent, is now used in a host of products including
  Microsoft Operations Manager, Microsoft Azure, and Microsoft Operations Management Suite.
sigma_id: 21541900-27a9-4454-9c4c-3f0a4240344a
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0004
  - TA0001
  - TA0002
techniques:
  - T1068
  - T1190
  - T1203
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: '2021-10-15'
modified: '2022-10-05'
falsepositives:
  - Legitimate use of SCX RunAsProvider Invoke_ExecuteShellCommand.
references:
  - https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure
  - https://github.com/Azure/Azure-Sentinel/pull/3059
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executeshellcommand.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: OMIGOD SCX RunAsProvider ExecuteShellCommand
id: 21541900-27a9-4454-9c4c-3f0a4240344a
status: test
description: |
    Rule to detect the use of the SCX RunAsProvider Invoke_ExecuteShellCommand to execute any UNIX/Linux command using the /bin/sh shell.
    SCXcore, started as the Microsoft Operations Manager UNIX/Linux Agent, is now used in a host of products including
    Microsoft Operations Manager, Microsoft Azure, and Microsoft Operations Management Suite.
references:
    - https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure
    - https://github.com/Azure/Azure-Sentinel/pull/3059
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021-10-15
modified: 2022-10-05
tags:
    - attack.privilege-escalation
    - attack.initial-access
    - attack.execution
    - attack.t1068
    - attack.t1190
    - attack.t1203
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        User: root
        LogonId: 0
        CurrentDirectory: '/var/opt/microsoft/scx/tmp'
        CommandLine|contains: '/bin/sh'
    condition: selection
falsepositives:
    - Legitimate use of SCX RunAsProvider Invoke_ExecuteShellCommand.
level: high
```
