---
title: Kavremover Dropped Binary LOLBIN Usage
summary: Detects the execution of a signed binary dropped by Kaspersky Lab Products Remover (kavremover) which can be abused as a LOLBIN to execute arbitrary commands and binaries.
sigma_id: d047726b-c71c-4048-a99b-2e2f50dc107d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1127
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-11-01'
falsepositives:
  - Unknown
references:
  - https://nasbench.medium.com/lolbined-using-kaspersky-endpoint-security-kes-installer-to-execute-arbitrary-commands-1c999f1b7fea
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_kavremover_uncommon_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Kavremover Dropped Binary LOLBIN Usage
id: d047726b-c71c-4048-a99b-2e2f50dc107d
status: test
description: Detects the execution of a signed binary dropped by Kaspersky Lab Products Remover (kavremover) which can be abused as a LOLBIN to execute arbitrary commands and binaries.
references:
    - https://nasbench.medium.com/lolbined-using-kaspersky-endpoint-security-kes-installer-to-execute-arbitrary-commands-1c999f1b7fea
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-11-01
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: ' run run-cmd '
    filter_main_legit_parents:
        ParentImage|endswith:
            - '\cleanapi.exe' # When launched from KES installer
            - '\kavremover.exe' # When launched from kavremover.exe
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
