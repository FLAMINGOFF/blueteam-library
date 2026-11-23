---
title: Linux Base64 Encoded Pipe to Shell
summary: Detects suspicious process command line that uses base64 encoded input for execution with a shell
sigma_id: ba592c6d-6888-43c3-b8c6-689b8fe47337
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics: []
techniques:
  - T1140
author: pH-T (Nextron Systems)
date: '2022-07-26'
modified: '2023-06-16'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/arget13/DDexec
  - https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_base64_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Linux Base64 Encoded Pipe to Shell
id: ba592c6d-6888-43c3-b8c6-689b8fe47337
status: test
description: Detects suspicious process command line that uses base64 encoded input for execution with a shell
references:
    - https://github.com/arget13/DDexec
    - https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally
author: pH-T (Nextron Systems)
date: 2022-07-26
modified: 2023-06-16
tags:
    - attack.stealth
    - attack.t1140
logsource:
    product: linux
    category: process_creation
detection:
    selection_base64:
        CommandLine|contains: 'base64 '
    selection_exec:
        - CommandLine|contains:
              - '| bash '
              - '| sh '
              - '|bash '
              - '|sh '
        - CommandLine|endswith:
              - ' |sh'
              - '| bash'
              - '| sh'
              - '|bash'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activities
level: medium
```
