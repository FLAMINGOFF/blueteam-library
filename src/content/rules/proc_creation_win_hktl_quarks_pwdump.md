---
title: HackTool - Quarks PwDump Execution
summary: Detects usage of the Quarks PwDump tool via commandline arguments
sigma_id: 0685b176-c816-4837-8e7b-1216f346636b
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.002
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-05'
modified: '2026-11-05'
falsepositives:
  - Unlikely
references:
  - https://github.com/quarkslab/quarkspwdump
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/seedworm-apt-iran-middle-east
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_quarks_pwdump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Quarks PwDump Execution
id: 0685b176-c816-4837-8e7b-1216f346636b
status: test
description: Detects usage of the Quarks PwDump tool via commandline arguments
references:
    - https://github.com/quarkslab/quarkspwdump
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/seedworm-apt-iran-middle-east
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-05
modified: 2026-11-05
tags:
    - attack.credential-access
    - attack.t1003.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\QuarksPwDump.exe'
    selection_cli:
        CommandLine|contains:
            - ' -dhl'
            - ' --dump-hash-local'
            - ' -dhdc'
            - ' --dump-hash-domain-cached'
            - ' --dump-bitlocker'
            - ' -dhd '
            - ' --dump-hash-domain '
            - '--ntds-file'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high
```
