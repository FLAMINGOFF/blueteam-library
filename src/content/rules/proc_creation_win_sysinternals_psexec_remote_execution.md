---
title: Potential PsExec Remote Execution
summary: Detects potential psexec command that initiate execution on a remote systems via common commandline flags used by the utility
sigma_id: ea011323-7045-460b-b2d7-0f7442ea6b38
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0042
techniques:
  - T1587.001
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: '2023-02-28'
modified: '2025-09-01'
falsepositives:
  - Unknown
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
  - https://www.poweradmin.com/paexec/
  - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_psexec_remote_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential PsExec Remote Execution
id: ea011323-7045-460b-b2d7-0f7442ea6b38
status: test
description: Detects potential psexec command that initiate execution on a remote systems via common commandline flags used by the utility
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
    - https://www.poweradmin.com/paexec/
    - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-28
modified: 2025-09-01
tags:
    - attack.resource-development
    - attack.t1587.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Accepting EULA in commandline - often used in automated attacks
        CommandLine|contains|all:
            - 'accepteula'
            - ' -u '
            - ' -p '
            - ' \\\\'
    filter_main_localhost:
        CommandLine|contains:
            - '\\\\localhost'
            - '\\\\127.'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
