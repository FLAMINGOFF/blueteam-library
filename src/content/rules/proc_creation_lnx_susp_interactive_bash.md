---
title: Interactive Bash Suspicious Children
summary: Detects suspicious interactive bash as a parent to rather uncommon child processes
sigma_id: ea3ecad2-db86-4a89-ad0b-132a10d2db55
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059.004
  - T1036
author: Florian Roth (Nextron Systems)
date: '2022-03-14'
falsepositives:
  - Legitimate software that uses these patterns
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_susp_interactive_bash.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Interactive Bash Suspicious Children
id: ea3ecad2-db86-4a89-ad0b-132a10d2db55
status: test
description: Detects suspicious interactive bash as a parent to rather uncommon child processes
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2022-03-14
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.004
    - attack.t1036
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        ParentCommandLine: 'bash -i'
    anomaly1:
        CommandLine|contains:
            - '-c import '
            - 'base64'
            - 'pty.spawn'
    anomaly2:
        Image|endswith:
            - 'whoami'
            - 'iptables'
            - '/ncat'
            - '/nc'
            - '/netcat'
    condition: selection and 1 of anomaly*
falsepositives:
    - Legitimate software that uses these patterns
level: medium
```
