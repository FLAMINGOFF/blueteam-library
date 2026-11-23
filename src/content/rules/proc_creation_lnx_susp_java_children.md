---
title: Suspicious Java Children Processes
summary: Detects java process spawning suspicious children
sigma_id: d292e0af-9a18-420c-9525-ec0ac3936892
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-03'
falsepositives:
  - Unknown
references:
  - https://www.tecmint.com/different-types-of-linux-shells/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_susp_java_children.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Java Children Processes
id: d292e0af-9a18-420c-9525-ec0ac3936892
status: test
description: Detects java process spawning suspicious children
references:
    - https://www.tecmint.com/different-types-of-linux-shells/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-03
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith: '/java'
        CommandLine|contains:
            - '/bin/sh'
            - 'bash'
            - 'dash'
            - 'ksh'
            - 'zsh'
            - 'csh'
            - 'fish'
            - 'curl'
            - 'wget'
            - 'python'
    condition: selection
falsepositives:
    - Unknown
level: high
```
