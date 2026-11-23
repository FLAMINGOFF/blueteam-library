---
title: Named Pipe Created Via Mkfifo
summary: Detects the creation of a new named pipe using the "mkfifo" utility
sigma_id: 9d779ce8-5256-4b13-8b6f-b91c602b43f4
status: test
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-06-16'
falsepositives:
  - Unknown
references:
  - https://dev.to/0xbf/use-mkfifo-to-create-named-pipe-linux-tips-5bbk
  - https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_mkfifo_named_pipe_creation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Named Pipe Created Via Mkfifo
id: 9d779ce8-5256-4b13-8b6f-b91c602b43f4
status: test
description: Detects the creation of a new named pipe using the "mkfifo" utility
references:
    - https://dev.to/0xbf/use-mkfifo-to-create-named-pipe-linux-tips-5bbk
    - https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-16
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/mkfifo'
    condition: selection
falsepositives:
    - Unknown
level: low
```
