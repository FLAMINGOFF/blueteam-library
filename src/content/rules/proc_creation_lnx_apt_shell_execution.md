---
title: Shell Invocation via Apt - Linux
summary: |-
  Detects the use of the "apt" and "apt-get" commands to execute a shell or proxy commands.
  Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
sigma_id: bb382fd5-b454-47ea-a264-1828e4c766d6
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0007
techniques:
  - T1083
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-12-28'
modified: '2024-09-02'
falsepositives:
  - Unknown
references:
  - https://gtfobins.github.io/gtfobins/apt/
  - https://gtfobins.github.io/gtfobins/apt-get/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_apt_shell_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Shell Invocation via Apt - Linux
id: bb382fd5-b454-47ea-a264-1828e4c766d6
status: test
description: |
    Detects the use of the "apt" and "apt-get" commands to execute a shell or proxy commands.
    Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/apt/
    - https://gtfobins.github.io/gtfobins/apt-get/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-28
modified: 2024-09-02
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/apt'
            - '/apt-get'
        CommandLine|contains: 'APT::Update::Pre-Invoke::='
    condition: selection
falsepositives:
    - Unknown
level: medium
```
